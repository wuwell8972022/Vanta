# Vanta：RingQ 的独立重制版

Vanta 是对 RingQ 项目的**功能等价重制**：把加密的 stage 交给一个内存加载器执行，支持本地文件、内嵌资源、远程 URL 三种投递方式，并附带资源伪造与诱饵生成工具链。

实现没有复用原项目的源码、目录结构、函数命名或打包格式：

| 维度 | RingQ 原项目 | Vanta |
|---|---|---|
| 加载器 | `RingQ.cpp`（MSVC + CRT） | `src/`（无 CRT、无导入表、C++17 freestanding） |
| 载荷格式 | 源版 XOR / 预编译版反转+Base64 | VENV/1 多层容器（ChaCha20 + 置换 + AEAD） |
| EXE 支持 | 依赖外部 `EXE2Shellcode.exe` 生成 shellcode | 加载器原生 PE32+ 手工映射，同时支持 raw shellcode |
| 加密 | 固定 XOR key `520520` | XChaCha20-Poly1305 + 流掩码 + 块置换 + PBKDF2 |
| 资源伪造 | `QVM250.py` + ResourceHacker + rcedit | Python 自实现 PE 资源节重建、版本信息、诱饵图标 |
| 字符串/API | 明文字符串、常规 IAT | 构建期加密字符串表 + PEB 遍历 + 哈希导出解析（零导入表） |
| 入口 | `main.txt` | `stage.venv`、RCDATA、路径/URL 提示资源、命令行参数 |

> 仅用于授权的安全研究、自有环境测试与防护验证。不要把它指向任何未授权的真实目标。

---

## 1. 快速开始

### 1.1 依赖

- Windows 10/11 x64
- LLVM：`clang++`、`lld-link`、`llvm-dlltool`（PATH 中可见）
- Python 3.10+（打包/伪造/测试）
  - 必需：无（核心 Python 代码只用标准库）
  - 推荐：`cryptography`（打包加速）、`Pillow`（诱饵图标）、`pefile`（forge 校验）
- 不需要 Visual Studio / Windows SDK 即可构建加载器（freestanding）

```powershell
pip install -r requirements.txt
```

### 1.2 构建

```powershell
cd vanta
python -I tools\gen_strings.py          # 重新生成加密字符串表（可选，默认已生成）
powershell -File build.ps1 -Dev        # 同时产出 release + dev
powershell -File lab\build_lab.ps1     # 构建良性测试载荷
```

输出：

- `build/vanta.exe`：生产版（Windows GUI 子系统，双击/运行不弹控制台窗口），反调试/反沙箱生效，静默运行
- `build/vanta_dev.exe`：开发版（Console 子系统，打印详细阶段日志），跳过调试器检测

构建脚本使用 `-ffreestanding -fno-exceptions -fno-rtti -fno-builtin`，链接器使用 `/nodefaultlib`，因此产物**没有导入表**，所有 Win32 API 通过 PEB 和导出哈希解析。

### 1.3 打包 stage

```powershell
python -I tools\loom.py pack lab\build\marker.exe -o stage.venv
```

`loom` 自动识别 PE32+ 与 raw shellcode；输出 VENV/1 容器。

```powershell
python -I tools\loom.py info stage.venv
python -I tools\loom.py unpack stage.venv -o recovered.bin
```

### 1.4 运行

把 `stage.venv` 放在 `vanta.exe` 同目录并执行：

```powershell
copy build\vanta.exe .\demo\
copy stage.venv .\demo\stage.venv
cd demo
.\vanta.exe
```

`vanta.exe` 是 GUI 子系统：双击或从命令行启动都不会打开控制台窗口，也不会输出日志。双击时 Windows 通常把工作目录设为 exe 所在目录，因此 sidecar 模式请把 `stage.venv` 与 exe 放在同一目录；否则用 forge 内嵌 stage，或把路径作为命令行参数（从 cmd/脚本启动）。需要观察过程时使用 `vanta_dev.exe`。

载荷获取顺序（先命中先执行）：

1. 命令行第一个非 `-` 参数（本地文件路径）
2. 当前工作目录 `stage.venv`
3. 内嵌资源 `RCDATA #0x4E58`（forge 注入的 stage）
4. 内嵌资源 `RCDATA #0x4E57`（UTF-8 路径或 `http(s)://` URL）
5. 都没有：做计时沙箱检测；若时间被加速，修补 ETW 并输出一段无害诱饵，然后退出

### 1.5 伪造资源 / 内嵌 stage

```powershell
# 生成一个带内嵌 stage、两个诱饵图标组、随机版本信息、512 字节 overlay 的变体
python -I tools\forge.py mutate build\vanta.exe -o variant.exe `
    --stage stage.venv --decoys 2 --overlay 512 --seed 42

# 批量化
python -I tools\forge.py batch build\vanta.exe -o variants --count 5 --stage stage.venv
```

`forge` 不修改任何代码节，只重建 `.rsrc` 并更新资源目录/大小/时间戳。

### 1.6 测试

```powershell
python -I tests\test_crypto.py
powershell -File tests\run_e2e.ps1
```

`run_e2e.ps1` 覆盖：Python 纯实现/加速实现、C++ KAT、sidecar、内嵌资源、自定义口令、基址重定位、raw shellcode、零导入与明文审计。

---

## 2. 目录结构

```
vanta/
├─ include/vanta/
│  ├─ base.hpp          # 类型、FNV 哈希、内存/杂音工具
│  ├─ win32.hpp         # 最小 Win32/PE 结构体与常量（编译期断言布局）
│  ├─ api.hpp           # PEB 模块枚举、哈希导出解析、API 缓存
│  ├─ crypto.hpp        # SHA-256/HMAC/PBKDF2/ChaCha20/Poly1305/XChaCha
│  ├─ env.hpp           # VENV/1 容器
│  ├─ pe.hpp            # PE 手工映射
│  └─ gen_strings.hpp   # 自动生成的加密字符串表
├─ src/
│  ├─ api.cpp           # PEB 解析、转发导出、freestanding mem*
│  ├─ crypto.cpp        # 纯 C++ 密码学实现
│  ├─ env.cpp           # 外层掩码、KDF、AEAD、反置换、LZSS
│  ├─ pe.cpp            # 重定位、导入/延迟导入、节权限、入口调用
│  └─ entry.cpp         # 编排、投递、反分析、口令组装、执行
├─ tools/
│  ├─ loom.py           # 打包 CLI
│  ├─ loom_pkg/         # 容器/密码学/LZSS 实现
│  ├─ forge.py          # 资源伪造 CLI
│  ├─ forge_pkg/        # PE 编辑、资源树、版本信息、图标
│  ├─ gen_strings.py    # 加密字符串表生成器
│  ├─ strings.json      # 需要隐藏的字符串清单
│  └─ audit_binary.py   # 零导入/明文泄漏审计
├─ lab/
│  ├─ marker.cpp        # 良性测试载荷（写标记文件 + 重定位回调）
│  ├─ build_lab.ps1
│  └─ kernel32.def
├─ tests/
│  ├─ test_crypto.py
│  ├─ kat.cpp
│  ├─ make_vector.py
│  └─ run_e2e.ps1
└─ docs/
   ├─ ANALYSIS_RINGQ.md # 原项目完整逆向分析
   ├─ ARCHITECTURE.md   # 重制版架构与数据流
   ├─ CRYPTO.md         # 容器格式与密码学设计
   └─ BUILD.md          # 构建/部署/排错
```

---

## 3. 混淆与保护要点

1. **零导入表**：链接时不引用任何导入符号；`LoadLibraryA`/`GetProcAddress` 等全部从 PEB 的 `InMemoryOrderModuleList` 找到模块，再按导出名 FNV-1a 哈希匹配。kernel32 的转发导出（→ kernelbase）会被递归跟随。
2. **字符串全加密**：`tools/gen_strings.py` 为每个字符串生成独立 64 位密钥和密文字节，加载器用 `volatile` 读取密文，阻止 Clang 常量折叠。二进制中不存在 `stage.venv`、`wininet.dll`、KDF 标签、默认口令片段等明文。
3. **口令三段拆分**：默认口令分别以“加密字符串 / MBA 编码的 u32 数组 / 异或字节数组”存放，运行时拼接后立即使用并擦除；也可通过 `RCDATA 0x4E59` 覆盖（forge 会先用固定掩码异或，避免二进制中出现自定义口令明文）。
4. **多层密码学**：外层 ChaCha20 掩码 → PBKDF2 → 块置换 → 流掩码 → XChaCha20-Poly1305（头部作为 AAD）→ LZSS。任何一层校验失败都不会进入执行阶段。
5. **反分析**：PEB `BeingDebugged`、`NtGlobalFlag`、`NtQueryInformationProcess` 调试端口/调试对象检测；计时沙箱检测；诱饵分支修补 `ntdll!EtwEventWrite`（`xor eax,eax; ret`）。
6. **执行保护**：载荷先解密到独立内存，AEAD + 截断 SHA-256 校验通过后才映射/执行；raw shellcode 以 `PAGE_EXECUTE_READ` 执行，执行后恢复权限；密钥、明文、stage 缓冲区全部擦除。
7. **诱饵资源**：随机图标组、随机版本信息、随机时间戳、overlay，结构与原 QVM250 的“资源伪造”目标一致，但完全由自研 PE 写入器完成。

更多细节见 [docs/CRYPTO.md](docs/CRYPTO.md) 与 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

---

## 4. 与原项目的差异

- **原生 PE 映射**：不再需要 `EXE2Shellcode.exe`。`loom pack app.exe` 直接把完整 PE32+ 放入容器，加载器完成重定位、导入解析、节权限设置并调用入口。raw shellcode 仍支持。
- **格式与命名独立**：`VENV/1` 容器、`stage.venv`、资源 ID `0x4E57/58/59`、模块名 `vanta/loom/forge` 均为自主设计。
- **源版 vs 预编译版的差异已修正**：原仓库源码使用 XOR `520520`，而预编译 `Create.exe` 使用“内嵌 0x12E9 反射 stub + 反转 + 自定义 Base64”。Vanta 以源码语义为基线，但用现代容器替换了弱 XOR。
- **可靠性**：原反射 stub 在目标无重定位且首选基址被占用时会静默失败；Vanta 的手工映射器在 `VirtualAlloc(preferred)` 失败后回退到任意基址并应用 `.reloc`，无重定位则明确失败。
- **抗分析**：原项目只有计时检查和 ETW 修补；Vanta 增加调试器检测、字符串加密、导入隐藏、AEAD 头部认证。

---

## 5. 已知限制

- 仅支持 x64 Windows；PE 载荷必须是 PE32+ x64。
- 手工映射不在 PEB 中注册模块：依赖 `GetModuleHandle(NULL)` 的载荷、TLS 回调、C++ 异常/SEH 函数表、CFG/CET 元数据的载荷可能失败。
- 不处理签名证书；forge 修改资源会使已有 Authenticode 签名失效。
- 嵌入的口令与密钥最终都可从加载器中提取；这是提高分析成本，不是密码学意义上的“不可提取”。
- 反调试可能导致在调试器下静默退出；调试请用 `vanta_dev.exe`。
- `forge` 的诱饵图标依赖 Pillow；`pefile` 仅用于校验，未安装时自动跳过。
- 原仓库的预编译二进制与源码不同代；Vanta 不复刻该二进制行为，而是实现等价能力。

---

## 6. 构建输出与部署

生产部署通常只需要：

```
vanta.exe          # 或经 forge 生成的变体
stage.venv         # 或把 stage 注入变体的 RCDATA
```

若使用内嵌 stage，则只需单个 exe。`vanta_dev.exe` 不应分发（包含阶段日志且关闭调试器检测）。
