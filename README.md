# FarFarWest Mod Injector

FarFarWest 游戏的 DLL 注入器，用于将 mod DLL 注入到游戏进程中。

作者: songzhearen

## 构建

需要 MinGW-w64 和 CMake：

```bash
cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

生成的可执行文件位于 `build/ffwinject.exe`。

## 使用

1. 运行 `ffwinject.exe`
2. 点击 **浏览** 选择 mod DLL 文件
3. 启动游戏
4. 点击 **注入** 或勾选 **自动注入**
