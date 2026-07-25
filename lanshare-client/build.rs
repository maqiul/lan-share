fn main() {
    winfsp::build::winfsp_link_delayload();

    // Windows 下内嵌应用图标（资源序号 1）：
    // 供资源管理器显示 exe 图标，托盘亦从模块资源加载同一图标。
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        let mut res = winres::WindowsResource::new();
        res.set_icon("assets/lanshare.ico");
        if let Err(e) = res.compile() {
            // 资源编译器缺失时不阻断构建，仅告警
            println!("cargo:warning=嵌入图标失败: {}", e);
        }
    }
}
