import json
import base64
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
import math
import io

@dataclass
class FractalPoint:
    x: float
    y: float
    r: int
    g: int
    b: int

@dataclass
class IFSTransform:
    a: float = 0.0
    b: float = 0.0
    c: float = 0.0
    d: float = 0.0
    e: float = 0.0
    f: float = 0.0

class FractalEncryption:
    DEFAULT_IFS = [
        IFSTransform(a=0.00, b=0.00, c=0.00, d=0.16, e=0.00, f=0.00),
        IFSTransform(a=0.85, b=0.04, c=-0.04, d=0.85, e=0.00, f=1.60),
        IFSTransform(a=0.20, b=-0.26, c=0.23, d=0.22, e=0.00, f=1.60),
        IFSTransform(a=-0.15, b=0.28, c=0.26, d=0.24, e=0.00, f=0.44)
    ]

    def __init__(self, ifs_transforms: Optional[List[IFSTransform]] = None):
        self.ifs = ifs_transforms or self.DEFAULT_IFS.copy()
        self.chunk_size = 5000

    def data_to_bit_stream(self, data: bytes) -> str:
        return ''.join(format(byte, '08b') for byte in data)

    def bit_stream_to_data(self, bit_stream: str) -> bytes:
        bytes_list = []
        for i in range(0, len(bit_stream), 8):
            byte_str = bit_stream[i:i+8]
            if len(byte_str) == 8:
                bytes_list.append(int(byte_str, 2))
        return bytes(bytes_list)

    def apply_transform(self, transform: IFSTransform, point: Tuple[float, float]) -> Tuple[float, float]:
        x, y = point
        new_x = transform.a * x + transform.b * y + transform.e
        new_y = transform.c * x + transform.d * y + transform.f
        return (new_x, new_y)

    def encrypt_data(self, data: bytes, filename: str = "encrypted",
                    progress_callback: Optional[callable] = None) -> Dict[str, Any]:
        bit_stream = self.data_to_bit_stream(data)
        remainder = len(bit_stream) % 26
        if remainder != 0:
            bit_stream += '0' * (26 - remainder)

        points = []
        current_point = (0.0, 0.0)
        total_iterations = len(bit_stream) // 26

        for i in range(0, len(bit_stream), 26):
            if progress_callback and i % (self.chunk_size * 26) == 0:
                progress = (i // 26) / total_iterations * 100
                progress_callback(progress, f"Encrypting")

            transform_index = int(bit_stream[i:i+2], 2)
            r = int(bit_stream[i+2:i+10], 2)
            g = int(bit_stream[i+10:i+18], 2)
            b = int(bit_stream[i+18:i+26], 2)

            transform = self.ifs[transform_index % len(self.ifs)]
            new_point = self.apply_transform(transform, current_point)
            points.append(FractalPoint(x=new_point[0], y=new_point[1], r=r, g=g, b=b))
            current_point = new_point

        if progress_callback:
            progress_callback(100, "Encryption complete")

        return {
            "original_filename": filename,
            "points": [{"x": p.x, "y": p.y, "r": p.r, "g": p.g, "b": p.b} for p in points],
            "ifs_key": [{"a": t.a, "b": t.b, "c": t.c, "d": t.d, "e": t.e, "f": t.f} for t in self.ifs],
            "metadata": {"original_size": len(data)}
        }

    def decrypt_data(self, fractal_data: Dict[str, Any],
                    progress_callback: Optional[callable] = None) -> Tuple[bytes, str]:
        points_data = fractal_data["points"]
        if "ifs_key" in fractal_data:
            self.ifs = [IFSTransform(**t) for t in fractal_data["ifs_key"]]

        bit_stream = ""
        current_point = (0.0, 0.0)
        epsilon = 1e-9
        total_points = len(points_data)

        for i, point_data in enumerate(points_data):
            if progress_callback and i % self.chunk_size == 0:
                progress = (i / total_points) * 100
                progress_callback(progress, f"Decrypting")

            target_point = (point_data["x"], point_data["y"])
            found = False
            for j, transform in enumerate(self.ifs):
                test_point = self.apply_transform(transform, current_point)
                if (abs(test_point[0] - target_point[0]) < epsilon and
                    abs(test_point[1] - target_point[1]) < epsilon):
                    bit_stream += format(j, '02b')
                    bit_stream += format(point_data["r"], '08b')
                    bit_stream += format(point_data["g"], '08b')
                    bit_stream += format(point_data["b"], '08b')
                    found = True
                    break
            if not found:
                raise ValueError(f"Decryption failed: Could not match point {i}")
            current_point = target_point

        if progress_callback:
            progress_callback(100, "Decryption complete")

        decrypted_data = self.bit_stream_to_data(bit_stream)
        original_size = fractal_data.get("metadata", {}).get("original_size")
        if original_size and len(decrypted_data) > original_size:
            decrypted_data = decrypted_data[:original_size]

        filename = fractal_data.get("original_filename", "decrypted_file")
        return decrypted_data, filename

    def create_fractal_image(self, fractal_data: Dict[str, Any],
                           width: int = 800, height: int = 800) -> bytes:
        try:
            from PIL import Image, ImageDraw
        except ImportError:
            raise ImportError("Pillow is required for image generation: pip install Pillow")

        img = Image.new('RGB', (width, height), (0, 0, 0))
        draw = ImageDraw.Draw(img)
        points = fractal_data["points"]

        if points:
            x_coords = [p["x"] for p in points]
            y_coords = [p["y"] for p in points]
            x_min, x_max = min(x_coords), max(x_coords)
            y_min, y_max = min(y_coords), max(y_coords)
            x_range = x_max - x_min or 1
            y_range = y_max - y_min or 1
            scale = min((width * 0.9) / x_range, (height * 0.9) / y_range)
            x_offset = width/2 - (x_min + x_range/2) * scale
            y_offset = height/2 - (y_min + y_range/2) * scale

            for p in points:
                x = int(p["x"] * scale + x_offset)
                y = int(p["y"] * scale + y_offset)
                if 0 <= x < width and 0 <= y < height:
                    draw.point((x, y), fill=(p["r"], p["g"], p["b"]))
        
        img_bytes = io.BytesIO()
        img.save(img_bytes, format='PNG')
        return img_bytes.getvalue()

    def get_ifs_from_string(self, ifs_string: str) -> List[IFSTransform]:
        transforms = []
        for line in ifs_string.split('\n'):
            if ':' in line:
                params_str = line.split(':')[1]
                params = {k.strip(): float(v.strip()) for k, v in (p.split('=') for p in params_str.split(','))}
                transforms.append(IFSTransform(**params))
        return transforms