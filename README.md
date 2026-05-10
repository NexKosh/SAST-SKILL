# go-callmap

Go 靜態分析工具，基於 RTA（Rapid Type Analysis）建立 call graph。只追蹤 project-owned 的 package，在抵達外部 package 邊界時停止標記。

**設計原則：純事實輸出，不做任何安全判斷。** 判斷工作交給 LLM。

---

## 前置需求

在 repo root 安裝依賴：

```powershell
go get golang.org/x/tools/go/callgraph/rta
go get golang.org/x/tools/go/packages
go get golang.org/x/tools/go/ssa
go get golang.org/x/tools/go/ssa/ssautil
```

---

## 用法

```
go run ./_tools/main.go [flags]
```

### Flags

| Flag | 必填 | 說明 | 預設 |
|------|------|------|------|
| `-module` | ✓ | 自己的 module prefix，逗號分隔多個 | — |
| `-pkg` | | 要分析的 package pattern | `./...` |
| `-entry` | | entry point 模式（見下方說明） | `main` |
| `-boundary` | | 額外的 boundary package，逗號分隔 | — |
| `-format` | | 輸出格式：`text` / `json` | `text` |
| `-list-entry` | | 只列出所有 entry point，不跑 call graph | `false` |

### `-entry` 模式

| 值 | 行為 |
|----|------|
| `main` | 找所有 package 裡的 `main()`，適合 CLI tool |
| `web` | 自動偵測 web handler signature，支援 gin / echo / fiber / net/http / chi / fasthttp，包含 struct method |
| 任意名稱 | 找所有 package 裡該名稱的 function，例如 `-entry NewServer` |

### `-boundary` 格式

新增額外的 boundary package，到達這些 package 時停止追蹤並標記：

```
-boundary "gorm.io/gorm,github.com/redis/go-redis"
```

---

## 範例

### 只列出所有 web 入口點

```powershell
go run ./_tools/main.go `
  -module "github.com/specterops/bloodhound" `
  -pkg "./cmd/api/src/..." `
  -entry web `
  -list-entry
```

輸出：
```
(*github.com/specterops/bloodhound/cmd/api/src/api/v2.Resources).GetUser
(*github.com/specterops/bloodhound/cmd/api/src/api/v2.Resources).CreateUser
...
```

### 列出入口點（JSON 格式）

```powershell
go run ./_tools/main.go `
  -module "github.com/specterops/bloodhound" `
  -pkg "./cmd/api/src/..." `
  -entry web `
  -list-entry -format json 2>$null | Out-File entries.json -Encoding utf8
```

### CLI tool call graph

```powershell
go run ./_tools/main.go `
  -module "github.com/specterops/bloodhound" `
  -pkg "./cmd/sharphound-ingest/..." `
  -entry main 2>$null
```

### Web app call graph

```powershell
go run ./_tools/main.go `
  -module "github.com/specterops/bloodhound" `
  -pkg "./cmd/api/src/..." `
  -entry web 2>$null
```

### 多個 module + 額外 boundary

```powershell
go run ./_tools/main.go `
  -module "github.com/myorg/app,github.com/myorg/lib" `
  -pkg "./..." `
  -entry web `
  -boundary "gorm.io/gorm,github.com/aws/aws-sdk-go" 2>$null
```

### 存成檔案

```powershell
# text
go run ./_tools/main.go `
  -module "github.com/specterops/bloodhound" `
  -pkg "./cmd/api/src/..." `
  -entry web 2>$null | Out-File callgraph.txt -Encoding utf8

# json
go run ./_tools/main.go `
  -module "github.com/specterops/bloodhound" `
  -pkg "./cmd/api/src/..." `
  -entry web -format json 2>$null | Out-File callgraph.json -Encoding utf8
```

---

## 輸出格式

診斷資訊（entry point 數量等）輸出到 **stderr**，實際資料輸出到 **stdout**，存檔時不會混在一起。

### text 格式

```
[CALL]     caller → callee
[BOUNDARY] caller → (callee_pkg).function
```

| 類型 | 意義 |
|------|------|
| `[CALL]` | project 內部的 function call |
| `[BOUNDARY]` | 呼叫到外部 package，追蹤在此停止 |

### json 格式

```json
[
  {
    "caller": "github.com/myorg/app/handler.GetUser",
    "callee": "QueryRow",
    "callee_pkg": "database/sql",
    "boundary": true
  },
  {
    "caller": "github.com/myorg/app/handler.GetUser",
    "callee": "github.com/myorg/app/repository.FindUser",
    "callee_pkg": "github.com/myorg/app/repository",
    "boundary": false
  }
]
```

---

## 預設 boundary package 清單

到達以下 package 時停止追蹤：

| Package |
|---------|
| `database/sql` |
| `os/exec` |
| `net/http` |
| `os` |
| `io/ioutil` |
| `html/template` |
| `text/template` |
| `crypto` |
| `encoding/xml` |
| `archive/zip` |
| `path/filepath` |

用 `-boundary` 可以新增，不影響預設清單。

---

## 設計原則

- **純事實輸出**：只描述呼叫關係，不判斷是否有安全問題，不貼分類標籤
- **只追蹤 project-owned code**：遇到外部 package 就停止，標記 `[BOUNDARY]`
- **包含 struct method**：web 模式會掃 struct method，不只是 top-level function
- **stderr / stdout 分離**：診斷訊息進 stderr，資料進 stdout
- **RTA 演算法**：比 CHA 精確，比 pointer analysis 快
- **不含 vendor**：`/vendor` 子目錄自動排除在 project-owned 之外
