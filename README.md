# Vanta 使用指南

**运行 `vanta.exe`** 和 **打包 `stage.venv`**。

---

## 一、运行 vanta.exe

### 1. 最简 sidecar 用法

把 `stage.venv` 和 `vanta.exe` 放在同一目录：

```text
run/
├─ vanta.exe
└─ stage.venv
```

然后双击 `vanta.exe`，或在命令行运行：

```powershell
cd run
.\vanta.exe
```

`vanta.exe` 是 GUI 子系统：双击或运行都不会弹出控制台窗口，也不会输出日志。

### 2. 指定 stage 路径

```powershell
.\vanta.exe "D:\payloads\stage.venv"
```

支持带空格的引号路径。

查找顺序：

1. 命令行第一个非 `-` 参数
2. 当前工作目录的 `stage.venv`
3. 内嵌资源（如果 loader 被 forge 内嵌过）
4. 没有任何 stage → 静默退出

### 3. 双击时的目录

双击 `vanta.exe` 时，Windows 通常把工作目录设为 exe 所在目录，所以：

```text
D:\run\
├─ vanta.exe
└─ stage.venv
```

双击即可。若通过快捷方式启动，注意快捷方式的“起始位置”。

### 4. 从脚本启动并等待

GUI 程序从 cmd 启动时可能立即返回。需要等待执行结束：

```powershell
Start-Process .\vanta.exe -WorkingDirectory . -Wait
```

### 5. 退出码

| 退出码 | 含义 |
|---|---|
| `0` | 成功，或无 stage 正常退出 |
| `2` | 容器被拒绝（口令错误/完整性失败） |
| `3` | PE 映射失败 |
| `4` | 口令组装失败 |
| 其他 | 载荷入口返回值，或载荷自行退出 |

### 6. 自定义口令的限制

如果只使用现有的 `vanta.exe`，打包时**不要**加 `--passphrase`，使用默认口令：

```powershell
python -I tools\loom.py pack payload.exe -o stage.venv
```

如果 stage 用了自定义口令，加载器也必须持有同一口令（内嵌 `RCDATA 0x4E59` 或重新编译），否则会报 `env: aead` / `vanta: envelope rejected`。

---

## 二、打包 stage.venv

### 1. 直接使用项目中的 loom

在 `vanta` 目录：

# PE32+ x64 原生程序
python -I tools\loom.py pack payload.exe -o stage.venv

# raw x64 shellcode
python -I tools\loom.py pack payload.bin -o stage.venv
```

`loom` 自动识别：

- `MZ` + PE32+ + AMD64 → 标记为 PE，加载器手工映射；
- 其他内容 → raw shellcode。

### 2. 常用参数

```powershell
# 不压缩
python -I loom.py pack payload.exe -o stage.venv --no-compress

# 自定义 PBKDF2 轮数
python -I loom.py pack payload.exe -o stage.venv --rounds 200000

# 强制按 raw shellcode 处理
python -I loom.py pack payload.bin -o stage.venv --force-raw

# 强制要求 PE32+ x64
python -I loom.py pack payload.exe -o stage.venv --force-pe
```

### 3. 验证容器

```powershell
# 查看元数据
python -I loom.py info stage.venv

# 解出原始 payload 对比
python -I loom.py unpack stage.venv -o recovered.bin
```

如果 `info` 报：

```text
bad envelope magic (wrong passphrase?)
```

说明口令不匹配或容器损坏。

### 5. 载荷格式要求

| 类型 | 是否支持 | 说明 |
|---|---|---|
| PE32+ x64 原生 EXE/DLL | 是 | 手工映射 |
| raw x64 shellcode | 是 | 直接执行 |
| PE32 / x86 | 否 | x64 加载器不能执行 |
| .NET 程序集 | 否 | 需要 CLR 宿主，不能直接 pack |

注意：

- raw shellcode 必须是 x64；
- 以 `MZ` 开头但不是 PE32+ x64 的文件会被拒绝；
- `--force-raw` 不能把 PE 变成可执行 shellcode，只会导致崩溃；
- PE 若无重定位表且首选基址被占用，映射可能失败。

---

## 三、最短完整流程

# 1. 打包
python -I tools\loom.py pack payload.exe -o stage.venv

# 2. 部署
mkdir run
copy build\vanta.exe run\
copy stage.venv run\

# 3. 运行
cd run
.\vanta.exe
```

单文件部署需要 forge 把 stage 内嵌；本指南不展开。

---

## 四、常见问题

| 现象 | 原因 | 处理 |
|---|---|---|
| 双击没反应 | GUI 子系统无控制台，且可能没找到 stage | 确认 `stage.venv` 同目录，或传绝对路径 |
| `env: aead` | 口令不匹配/容器损坏 | 用默认口令重新打包，或用 `loom info` 自检 |
| `vanta: envelope rejected` | 容器被拒绝 | 检查 stage 是否由 loom 生成 |
| `pe: no base relocation directory` | PE 无 `.reloc` 且基址被占用 | 重新链接 `/dynamicbase /fixed:no` |
| `pe: TLS directory present` | 载荷有 TLS 回调，映射器不执行 | 改用 raw shellcode |
| `pe: named import missing` | 导入无法解析 | 检查依赖 DLL/API |
| raw 执行后崩溃 | x86 shellcode 或依赖不匹配 | 使用 x64 payload |
| `input looks like a PE but is not PE32+ x86-64` | .NET/PE32/x86 | 转换成 x64 原生或 x64 shellcode |