package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/token"
	"go/types"
	"os"
	"strings"

	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// Edge represents a single call relationship
type Edge struct {
	Caller    string `json:"caller"`
	Callee    string `json:"callee"`
	CalleePkg string `json:"callee_pkg"`
	Boundary  bool   `json:"boundary"` // true = 離開 project-owned code
}

var modulePrefixes []string

func isProjectOwned(pkgPath string) bool {
	for _, prefix := range modulePrefixes {
		if strings.HasPrefix(pkgPath, prefix) &&
			!strings.HasPrefix(pkgPath, prefix+"/vendor") {
			return true
		}
	}
	return false
}

// boundaryPkgs 是工具會在邊界停下來標記的外部 package
// 純事實，不含任何判斷或分類標籤
var boundaryPkgs = []string{
	"database/sql",
	"os/exec",
	"net/http",
	"os",
	"io/ioutil",
	"html/template",
	"text/template",
	"crypto",
	"encoding/xml",
	"archive/zip",
	"path/filepath",
}

func parseBoundaryFlag(raw string) {
	for _, item := range strings.Split(raw, ",") {
		if item = strings.TrimSpace(item); item != "" {
			boundaryPkgs = append(boundaryPkgs, item)
		}
	}
}

func isBoundaryPkg(pkgPath string) bool {
	for _, prefix := range boundaryPkgs {
		if strings.HasPrefix(pkgPath, prefix) {
			return true
		}
	}
	return false
}

// Web handler signatures
var handlerSignatures = []struct {
	paramCount int
	typeHints  []string
}{
	{2, []string{"http.ResponseWriter", "http.Request"}},
	{1, []string{"gin.Context"}},
	{1, []string{"echo.Context"}},
	{1, []string{"fiber.Ctx"}},
	{1, []string{"fasthttp.RequestCtx"}},
}

func isWebHandler(fn *ssa.Function) bool {
	params := fn.Signature.Params()
	for _, h := range handlerSignatures {
		if params.Len() != h.paramCount {
			continue
		}
		matched := 0
		for i := 0; i < params.Len(); i++ {
			typStr := types.TypeString(params.At(i).Type(), nil)
			for _, hint := range h.typeHints {
				if strings.Contains(typStr, hint) {
					matched++
					break
				}
			}
		}
		if matched == h.paramCount {
			return true
		}
	}
	return false
}

func collectWebRoots(ssaPkgs []*ssa.Package) []*ssa.Function {
	var roots []*ssa.Function

	for _, pkg := range ssaPkgs {
		if pkg == nil || pkg.Pkg == nil {
			continue
		}
		if !isProjectOwned(pkg.Pkg.Path()) {
			continue
		}
		for _, member := range pkg.Members {
			switch m := member.(type) {
			case *ssa.Function:
				if isWebHandler(m) {
					roots = append(roots, m)
				}
			case *ssa.Type:
				mset := pkg.Prog.MethodSets.MethodSet(types.NewPointer(m.Type()))
				for i := 0; i < mset.Len(); i++ {
					fn := pkg.Prog.MethodValue(mset.At(i))
					if fn != nil && isWebHandler(fn) {
						roots = append(roots, fn)
					}
				}
			}
		}
	}

	return roots
}

func collectNamedRoots(ssaPkgs []*ssa.Package, name string) []*ssa.Function {
	var roots []*ssa.Function
	for _, pkg := range ssaPkgs {
		if pkg == nil {
			continue
		}
		if fn := pkg.Func(name); fn != nil {
			roots = append(roots, fn)
		}
	}
	return roots
}

func main() {
	moduleFlag    := flag.String("module", "", "module prefix，逗號分隔")
	pkgFlag       := flag.String("pkg", "./...", "要分析的 package pattern")
	entryFlag     := flag.String("entry", "main", "entry point：main / web / 任意 function 名稱")
	boundaryFlag  := flag.String("boundary", "", "額外的 boundary package，逗號分隔\n例如：gorm.io/gorm,github.com/redis/go-redis")
	formatFlag    := flag.String("format", "text", "輸出格式：text / json")
	listEntryFlag := flag.Bool("list-entry", false, "只列出所有 entry point，不跑 call graph")
	flag.Parse()

	if *moduleFlag == "" {
		fmt.Fprintln(os.Stderr, "error: -module is required")
		flag.Usage()
		os.Exit(1)
	}

	for _, m := range strings.Split(*moduleFlag, ",") {
		if m = strings.TrimSpace(m); m != "" {
			modulePrefixes = append(modulePrefixes, m)
		}
	}

	if *boundaryFlag != "" {
		parseBoundaryFlag(*boundaryFlag)
	}

	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedSyntax |
			packages.NeedTypes |
			packages.NeedTypesInfo |
			packages.NeedImports |
			packages.NeedDeps,
		Fset: fset,
	}

	pkgs, err := packages.Load(cfg, *pkgFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading packages: %v\n", err)
		os.Exit(1)
	}

	prog, ssaPkgs := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics)
	prog.Build()

	var roots []*ssa.Function
	if *entryFlag == "web" {
		roots = collectWebRoots(ssaPkgs)
	} else {
		roots = collectNamedRoots(ssaPkgs, *entryFlag)
	}

	if len(roots) == 0 {
		fmt.Fprintf(os.Stderr, "error: no entry points found (entry=%q)\n", *entryFlag)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "entry points: %d\n", len(roots))

	if *listEntryFlag {
		switch *formatFlag {
		case "json":
			var names []string
			for _, fn := range roots {
				names = append(names, fn.RelString(nil))
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(names)
		default:
			for _, fn := range roots {
				fmt.Println(fn.RelString(nil))
			}
		}
		return
	}

	result := rta.Analyze(roots, true)
	result.CallGraph.DeleteSyntheticNodes()

	var edges []Edge

	for fn, node := range result.CallGraph.Nodes {
		if fn == nil {
			continue
		}
		fnPkg := fn.Package()
		if fnPkg == nil || fnPkg.Pkg == nil {
			continue
		}
		if !isProjectOwned(fnPkg.Pkg.Path()) {
			continue
		}

		for _, edge := range node.Out {
			callee := edge.Callee.Func
			if callee == nil {
				continue
			}

			calleePkgPath := ""
			if cp := callee.Package(); cp != nil && cp.Pkg != nil {
				calleePkgPath = cp.Pkg.Path()
			}

			if isProjectOwned(calleePkgPath) {
				edges = append(edges, Edge{
					Caller:    fn.RelString(nil),
					Callee:    callee.RelString(nil),
					CalleePkg: calleePkgPath,
					Boundary:  false,
				})
			} else if isBoundaryPkg(calleePkgPath) {
				edges = append(edges, Edge{
					Caller:    fn.RelString(nil),
					Callee:    callee.Name(),
					CalleePkg: calleePkgPath,
					Boundary:  true,
				})
			}
		}
	}

	switch *formatFlag {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(edges)
	default:
		for _, e := range edges {
			if e.Boundary {
				fmt.Printf("[BOUNDARY] %s → (%s).%s\n", e.Caller, e.CalleePkg, e.Callee)
			} else {
				fmt.Printf("[CALL] %s → %s\n", e.Caller, e.Callee)
			}
		}
	}
}
