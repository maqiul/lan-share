# LanShare 客户端图标生成器
# 用法: powershell -ExecutionPolicy Bypass -File scripts\generate-icon.ps1
# 输出: lanshare-client\assets\lanshare.ico （多尺寸、PNG 压缩条目的 ICO）
#
# 设计：蓝色渐变圆角方块 + 白色「上传/共享」箭头（箭头 + U 形托盘），
# 寓意局域网文件共享。绘制于 256x256 母版后缩放至各尺寸。
Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = 'Stop'

function Draw-Master {
    $bmp = New-Object System.Drawing.Bitmap 256, 256
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.Clear([System.Drawing.Color]::Transparent)

    # 圆角矩形背景（蓝色渐变：左上亮 → 右下深）
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $r = 60; $d = $r * 2; $m = 10
    $path.AddArc($m, $m, $d, $d, 180, 90)
    $path.AddArc(246 - $d, $m, $d, $d, 270, 90)
    $path.AddArc(246 - $d, 246 - $d, $d, $d, 0, 90)
    $path.AddArc($m, 246 - $d, $d, $d, 90, 90)
    $path.CloseFigure()
    $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        (New-Object System.Drawing.Point 0, 0), (New-Object System.Drawing.Point 256, 256),
        [System.Drawing.Color]::FromArgb(255, 46, 140, 255),
        [System.Drawing.Color]::FromArgb(255, 13, 71, 161))
    $g.FillPath($brush, $path)
    $brush.Dispose(); $path.Dispose()

    $white = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::White)

    # 上传箭头：三角箭头 + 箭杆
    $head = @(
        (New-Object System.Drawing.Point 128, 38),
        (New-Object System.Drawing.Point 190, 108),
        (New-Object System.Drawing.Point 66, 108))
    $g.FillPolygon($white, $head)
    $g.FillRectangle($white, 108, 96, 40, 84)   # 箭杆 x=108..148, y=96..180

    # 底部托盘（U 形：左竖 + 右竖 + 底横）
    $g.FillRectangle($white, 48, 154, 26, 64)    # 左竖 x=48..74,  y=154..218
    $g.FillRectangle($white, 182, 154, 26, 64)   # 右竖 x=182..208, y=154..218
    $g.FillRectangle($white, 48, 192, 160, 26)   # 底横 x=48..208, y=192..218

    $white.Dispose(); $g.Dispose()
    return $bmp
}

$master = Draw-Master
$sizes = @(16, 20, 24, 32, 40, 48, 64, 96, 128, 256)
$pngs = New-Object System.Collections.ArrayList

foreach ($sz in $sizes) {
    if ($sz -eq 256) {
        $bmp = $master
    } else {
        $bmp = New-Object System.Drawing.Bitmap $sz, $sz
        $gg = [System.Drawing.Graphics]::FromImage($bmp)
        $gg.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $gg.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $gg.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $gg.DrawImage($master, 0, 0, $sz, $sz)
        $gg.Dispose()
    }
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    [void]$pngs.Add($ms.ToArray())
    $ms.Dispose()
    if ($sz -ne 256) { $bmp.Dispose() }
}
$master.Dispose()

# 组装 ICO 二进制（ICONDIR + ICONDIRENTRY[] + PNG 数据）
$out = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter $out
$bw.Write([UInt16]0)                 # reserved
$bw.Write([UInt16]1)                 # type = icon
$bw.Write([UInt16]$sizes.Count)      # count
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $sz = $sizes[$i]
    $w = if ($sz -ge 256) { [byte]0 } else { [byte]$sz }   # 256 编码为 0
    $png = $pngs[$i]
    $bw.Write($w); $bw.Write($w)      # width / height
    $bw.Write([byte]0); $bw.Write([byte]0)   # colorCount / reserved
    $bw.Write([UInt16]1); $bw.Write([UInt16]32)  # planes / bitCount
    $bw.Write([UInt32]$png.Length)   # bytesInRes
    $bw.Write([UInt32]$offset)       # imageOffset
    $offset += $png.Length
}
foreach ($png in $pngs) { $bw.Write([byte[]]$png) }
$bw.Flush()

$outDir = Join-Path $PSScriptRoot '..\lanshare-client\assets'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$outPath = Join-Path (Resolve-Path $outDir) 'lanshare.ico'
[System.IO.File]::WriteAllBytes($outPath, $out.ToArray())
$bw.Dispose(); $out.Dispose()
Write-Output ("OK: {0} ({1} bytes, {2} sizes)" -f $outPath, (Get-Item $outPath).Length, $sizes.Count)
