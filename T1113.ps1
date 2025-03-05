Add-Type -TypeDefinition @"
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Windows.Forms;
public class Screenshot {
    public static void CaptureScreen(string path) {
        Bitmap bmp = new Bitmap(Screen.PrimaryScreen.Bounds.Width, Screen.PrimaryScreen.Bounds.Height);
        Graphics g = Graphics.FromImage(bmp);
        g.CopyFromScreen(0, 0, 0, 0, bmp.Size);
        bmp.Save(path, ImageFormat.Png);
    }
}
"@ -Language CSharp

[Screenshot]::CaptureScreen("C:\screenshot.png")
