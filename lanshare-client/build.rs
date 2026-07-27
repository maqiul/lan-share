fn main() {
    #[cfg(windows)]
    {
        // WinFsp delayload 链接
        winfsp::build::winfsp_link_delayload();

        // 内嵌应用图标（资源序号 1）
        let mut res = winres::WindowsResource::new();
        res.set_icon("assets/lanshare.ico");
        if let Err(e) = res.compile() {
            println!("cargo:warning=嵌入图标失败: {}", e);
        }
    }
}
