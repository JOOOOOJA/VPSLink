$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Drawing
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$images=@()
foreach($size in @(16,20,24,32,40,48,64,128,256)) {
 $bitmap=[Drawing.Bitmap]::new($size,$size)
 $g=[Drawing.Graphics]::FromImage($bitmap)
 $g.SmoothingMode=[Drawing.Drawing2D.SmoothingMode]::AntiAlias
 $g.ScaleTransform($size/256.0,$size/256.0)
 $shape=[Drawing.Drawing2D.GraphicsPath]::new()
 foreach($arc in @(@(8,8,180),@(136,8,270),@(136,136,0),@(8,136,90))) {$shape.AddArc([single]$arc[0],[single]$arc[1],112,112,[single]$arc[2],90)}
 $shape.CloseFigure()
 $dark=[Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml('#15171c'))
 $border=[Drawing.Pen]::new([Drawing.ColorTranslator]::FromHtml('#343740'),3)
 $orange=[Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml('#ff9b35'))
 $light=[Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml('#fff4e4'))
 $warm=[Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml('#ffc76e'))
 $line=[Drawing.Pen]::new($orange,25)
 $line.StartCap=$line.EndCap=[Drawing.Drawing2D.LineCap]::Round
 $line.LineJoin=[Drawing.Drawing2D.LineJoin]::Round
 try {
  $g.FillPath($dark,$shape);$g.DrawPath($border,$shape)
  $g.DrawLines($line,[Drawing.PointF[]]@([Drawing.PointF]::new(66,78),[Drawing.PointF]::new(128,184),[Drawing.PointF]::new(190,78)))
  foreach($x in @(66,190)) {$g.FillEllipse($orange,$x-23,55,46,46);$g.FillEllipse($light,$x-10,68,20,20)}
  $g.FillEllipse($warm,113,169,30,30)
  $stream=[IO.MemoryStream]::new();$bitmap.Save($stream,[Drawing.Imaging.ImageFormat]::Png)
  $images+=,@{Size=$size;Bytes=$stream.ToArray()};$stream.Dispose()
  if($size -eq 256){$bitmap.Save((Join-Path $root 'assets\icon.png'),[Drawing.Imaging.ImageFormat]::Png)}
 } finally {foreach($obj in @($g,$bitmap,$shape,$dark,$border,$orange,$light,$warm,$line)){$obj.Dispose()}}
}
$file=[IO.File]::Create((Join-Path $root 'assets\VPSLink.ico'));$writer=[IO.BinaryWriter]::new($file)
try {
 $writer.Write([uint16]0);$writer.Write([uint16]1);$writer.Write([uint16]$images.Count)
 $offset=6+16*$images.Count
 foreach($img in $images){$dimension=if($img.Size -eq 256){0}else{$img.Size};$writer.Write([byte]$dimension);$writer.Write([byte]$dimension);$writer.Write([byte]0);$writer.Write([byte]0);$writer.Write([uint16]1);$writer.Write([uint16]32);$writer.Write([uint32]$img.Bytes.Length);$writer.Write([uint32]$offset);$offset+=$img.Bytes.Length}
 foreach($img in $images){$writer.Write([byte[]]$img.Bytes)}
}finally{$writer.Dispose()}
