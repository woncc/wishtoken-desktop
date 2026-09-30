from pathlib import Path
from PIL import Image, ImageDraw

root = Path(__file__).resolve().parent.parent / "assets"
root.mkdir(exist_ok=True)
im = Image.new("RGBA", (1024, 1024), (0, 0, 0, 0))
d = ImageDraw.Draw(im)
d.rounded_rectangle((16, 16, 1008, 1008), radius=232, fill="#3159e8")
d.rounded_rectangle((72, 72, 952, 952), radius=190, outline="#5f7cf0", width=4)
d.line((238, 333, 342, 689, 512, 433, 682, 689, 786, 333), fill="#ffffff", width=75, joint="curve")
d.ellipse((742, 235, 850, 343), fill="#70e5cf")
im.save(root / "icon.png")
im.save(root / "icon.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
im.save(root / "icon.icns")
