package main

import (
	"flag"
	"fmt"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

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

var securitySinks = map[string]string{
	"database/sql":  "SQL",
	"os/exec":       "RCE",
	"net/http":      "HTTP_CLIENT",
	"os":            "FILE_IO",
	"io/ioutil":     "FILE_IO",
	"html/template": "XSS",
	"text/template": "SSTI",
	"crypto":        "CRYPTO",
	"encoding/xml":  "XML",
	"archive/zip":   "ARCHIVE",
	"path/filepath": "PATH",
}

func parseSinkFlag(raw string) {
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 {
			fmt.Printf("warn: invalid sink format %q, expected pkg=LABEL\n", item)
			continue
		}
		securitySinks[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
}

func classifySink(pkgPath string) (string, bool) {
	for prefix, label := range securitySinks {
		if strings.HasPrefix(pkgPath, prefix) {
			return label, true
		}
	}
	return "", false
}

// Web handler signatures 各 framework
var handlerSignatures = []struct {
	framework  string
	paramCount int
	typeHints  []string
}{
	// net/http
	{"net/http", 2, []string{"http.ResponseWriter", "http.Request"}},
	// gin
	{"gin", 1, []string{"gin.Context"}},
	// echo
	{"echo", 1, []string{"echo.Context"}},
	// fiber
	{"fiber", 1, []string{"fiber.Ctx"}},
	// chi (net/http 相容)
	{"chi", 2, []string{"http.ResponseWriter", "http.Request"}},
	// fasthttp
	{"fasthttp", 1, []string{"fasthttp.RequestCtx"}},
}

func detectHandlerFramework(fn *ssa.Function) (framework string, ok bool) {
	sig := fn.Signature
	params := sig.Params()

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
			return h.framework, true
		}
	}
	return "", false
}

func collectWebRoots(ssaPkgs []*ssa.Package) []*ssa.Function {
	var roots []*ssa.Function
	detected := map[string]int{}

	for _, pkg := range ssaPkgs {
		if pkg == nil || pkg.Pkg == nil {
			continue
		}
		if !isProjectOwned(pkg.Pkg.Path()) {
			continue
		}
		for _, member := range pkg.Members {
			fn, ok := member.(*ssa.Function)
			if !ok {
				continue
			}
			if framework, ok := detectHandlerFramework(fn); ok {
				roots = append(roots, fn)
				detected[framework]++
			}
		}
	}

	if len(detected) > 0 {
		fmt.Println("=== Detected web frameworks ===")
		for fw, count := range detected {
			fmt.Printf("  %s: %d handlers\n", fw, count)
		}
		fmt.Println()
	}

	return roots
}

func collectMainRoots(ssaPkgs []*ssa.Package, entryName string) []*ssa.Function {
	var roots []*ssa.Function
	for _, pkg := range ssaPkgs {
		if pkg == nil {
			continue
		}
		if fn := pkg.Func(entryName); fn != nil {
			roots = append(roots, fn)
		}
	}
	return roots
}

func main() {
	moduleFlag := flag.String("module", "", "module prefix，逗號分隔")
	pkgFlag    := flag.String("pkg", "./...", "要分析的 package pattern")
	entryFlag  := flag.String("entry", "main", "entry point：main / web / 任意 function 名稱")
	sinkFlag   := flag.String("sink", "", "額外的 sink，格式：pkg前綴=標籤，逗號分隔\n例如：github.com/redis/go-redis=REDIS,gorm.io/gorm=ORM")
	flag.Parse()

	if *sinkFlag != "" {
		parseSinkFlag(*sinkFlag)
	}

	if *moduleFlag == "" {
		fmt.Println("error: -module is required")
		flag.Usage()
		return
	}

	for _, m := range strings.Split(*moduleFlag, ",") {
		if m = strings.TrimSpace(m); m != "" {
			modulePrefixes = append(modulePrefixes, m)
		}
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
		panic(err)
	}

	prog, ssaPkgs := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics)
	prog.Build()

	var roots []*ssa.Function
	if *entryFlag == "web" {
		roots = collectWebRoots(ssaPkgs)
	} else {
		roots = collectMainRoots(ssaPkgs, *entryFlag)
	}

	if len(roots) == 0 {
		fmt.Printf("error: no entry points found (entry=%q)\n", *entryFlag)
		return
	}

	fmt.Printf("=== Entry points: %d ===\n\n", len(roots))

	result := rta.Analyze(roots, true)
	result.CallGraph.DeleteSyntheticNodes()

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
				fmt.Printf("[INTERNAL] %s → %s\n",
					fn.RelString(nil),
					callee.RelString(nil),
				)
			} else if label, ok := classifySink(calleePkgPath); ok {
				fmt.Printf("[SINK:%s] %s → (%s).%s\n",
					label,
					fn.RelString(nil),
					calleePkgPath,
					callee.Name(),
				)
			}
		}
	}
}
