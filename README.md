# go-callmap

Go 靜態分析工具，基於 RTA（Rapid Type Analysis）建立 call graph，只追蹤 project-owned 的 package，並在抵達安全相關 sink 時停止標記。用於輔助 SAST，讓 LLM 不需要讀 source code 就能知道資料流向。

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
| `-sink` | | 額外的安全 sink 定義（見下方說明） | — |

### `-entry` 模式

| 值 | 行為 |
|----|------|
| `main` | 找所有 package 裡的 `main()` 當 entry point，適合 CLI tool |
| `web` | 自動偵測 web handler signature 當 entry point，支援 gin / echo / fiber / net/http / chi / fasthttp |
| 任意名稱 | 找所有 package 裡該名稱的 function，例如 `-entry NewServer` |

### `-sink` 格式

```
-sink "套件前綴=標籤,套件前綴=標籤"
```

新增或覆蓋預設 sink 定義，例如：

```
-sink "github.com/redis/go-redis=REDIS,gorm.io/gorm=ORM"
```

---

## 範例

### CLI tool

```powershell
go run ./_tools/main.go `
  -module "github.com/specterops/bloodhound" `
  -pkg "./cmd/sharphound-ingest/..." `
  -entry main
```

### Web 應用（自動偵測 framework）

```powershell
go run ./_tools/main.go `
  -module "github.com/myorg/myapp" `
  -pkg "./internal/..." `
  -entry web
```

### 多個 module + 自訂 sink

```powershell
go run ./_tools/main.go `
  -module "github.com/myorg/app,github.com/myorg/lib" `
  -pkg "./..." `
  -entry web `
  -sink "gorm.io/gorm=ORM,github.com/aws/aws-sdk-go=AWS"
```

### 存成檔案

```powershell
go run ./_tools/main.go `
  -module "github.com/specterops/bloodhound" `
  -pkg "./cmd/sharphound-ingest/..." `
  2>$null | Out-File callgraph.txt -Encoding utf8
```

---

## 輸出格式

```
=== Detected web frameworks ===    ← 只有 -entry web 才會出現
  gin: 23 handlers

=== Entry points: 23 ===

[INTERNAL] 呼叫方 → 被呼叫方       ← 兩端都是 project code
[SINK:標籤] 呼叫方 → (套件).函式   ← 抵達安全相關 sink
```

### 輸出類型說明

| 類型 | 意義 |
|------|------|
| `[INTERNAL]` | project 內部的 function call，LLM 繼續追蹤 |
| `[SINK:SQL]` | 呼叫到 `database/sql`，可能有 SQL injection 風險 |
| `[SINK:RCE]` | 呼叫到 `os/exec`，可能有 command injection 風險 |
| `[SINK:FILE_IO]` | 呼叫到 `os`，可能有 path traversal 風險 |
| `[SINK:HTTP_CLIENT]` | 呼叫到 `net/http` client，可能有 SSRF 風險 |
| `[SINK:XSS]` | 呼叫到 `html/template`，可能有 XSS 風險 |
| `[SINK:SSTI]` | 呼叫到 `text/template`，可能有 SSTI 風險 |
| `[SINK:XML]` | 呼叫到 `encoding/xml`，可能有 XXE 風險 |
| `[SINK:CRYPTO]` | 呼叫到 `crypto`，需確認演算法是否安全 |
| `[SINK:ARCHIVE]` | 呼叫到 `archive/zip`，可能有 ZIP slip 風險 |
| `[SINK:PATH]` | 呼叫到 `path/filepath`，可能有 path traversal 風險 |

---

## 預設 sink 清單

| 套件前綴 | 標籤 |
|----------|------|
| `database/sql` | `SQL` |
| `os/exec` | `RCE` |
| `net/http` | `HTTP_CLIENT` |
| `os` | `FILE_IO` |
| `io/ioutil` | `FILE_IO` |
| `html/template` | `XSS` |
| `text/template` | `SSTI` |
| `crypto` | `CRYPTO` |
| `encoding/xml` | `XML` |
| `archive/zip` | `ARCHIVE` |
| `path/filepath` | `PATH` |

---

## 設計原則

- **只追蹤 project-owned code**：遇到 stdlib 或第三方 package 就停止，改標記 sink 類型
- **RTA 演算法**：比 CHA 精確，比 pointer analysis 快，適合中大型 repo
- **不含 vendor**：`/vendor` 子目錄自動排除在 project-owned 之外
- **輸出給 LLM 用**：flat list 格式方便直接貼進 prompt，讓 LLM 針對 sink 點做漏洞驗證
