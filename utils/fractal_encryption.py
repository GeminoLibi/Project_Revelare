"""
Fractal Encryption Module for Project Revelare
Implements file encryption/decryption using Iterated Function Systems (IFS) fractals
"""

import json
import base64
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
import math
import io

@dataclass
class FractalPoint:
    """Represents a point in the fractal with RGB color data"""
    x: float
    y: float
    r: int
    g: int
    b: int

@dataclass
class IFSTransform:
    """Represents an Iterated Function System transform"""
    a: float = 0.0
    b: float = 0.0
    c: float = 0.0
    d: float = 0.0
    e: float = 0.0
    f: float = 0.0

class FractalEncryption:
    """
    Encrypts/decrypts files using fractal patterns.
    Data is encoded into the structure and colors of IFS fractals.
    """

    # Default Barnsley Fern IFS transforms
    DEFAULT_IFS = [
        IFSTransform(a=0.00, b=0.00, c=0.00, d=0.16, e=0.00, f=0.00),
        IFSTransform(a=0.85, b=0.04, c=-0.04, d=0.85, e=0.00, f=1.60),
        IFSTransform(a=0.20, b=-0.26, c=0.23, d=0.22, e=0.00, f=1.60),
        IFSTransform(a=-0.15, b=0.28, c=0.26, d=0.24, e=0.00, f=0.44)
    ]

    def __init__(self, ifs_transforms: Optional[List[IFSTransform]] = None):
        """
        Initialize fractal encryption with IFS transforms.

        Args:
            ifs_transforms: List of IFS transforms to use as encryption key
        """
        self.ifs = ifs_transforms or self.DEFAULT_IFS.copy()
        self.chunk_size = 5000  # Process points per iteration

    def data_to_bit_stream(self, data: bytes) -> str:
        """Convert binary data to bit stream"""
        return ''.join(format(byte, '08b') for byte in data)

    def bit_stream_to_data(self, bit_stream: str) -> bytes:
        """Convert bit stream back to binary data"""
        bytes_list = []
        for i in range(0, len(bit_stream), 8):
            byte_str = bit_stream[i:i+8]
            if len(byte_str) == 8:
                bytes_list.append(int(byte_str, 2))
        return bytes(bytes_list)

    def apply_transform(self, transform: IFSTransform, point: Tuple[float, float]) -> Tuple[float, float]:
        """Apply IFS transform to a point"""
        x, y = point
        new_x = transform.a * x + transform.b * y + transform.e
        new_y = transform.c * x + transform.d * y + transform.f
        return (new_x, new_y)

    def encrypt_data(self, data: bytes, filename: str = "encrypted",
                    progress_callback: Optional[callable] = None) -> Dict[str, Any]:
        """
        Encrypt data into fractal points.

        Args:
            data: Binary data to encrypt
            filename: Original filename
            progress_callback: Optional callback for progress updates

        Returns:
            Dictionary containing encrypted fractal data
        """
        bit_stream = self.data_to_bit_stream(data)

        # Pad bit stream to ensure it's divisible by 26 (2 bits for transform + 8*3 for RGB)
        remainder = len(bit_stream) % 26
        if remainder != 0:
            bit_stream += '0' * (26 - remainder)

        points = []
        current_point = (0.0, 0.0)  # Starting point

        total_iterations = len(bit_stream) // 26

        for i in range(0, len(bit_stream), 26):
            if progress_callback and i % (self.chunk_size * 26) == 0:
                progress = min(100, (i // 26) / total_iterations * 100)
                progress_callback(progress, f"Encrypting: {i//26}/{total_iterations} points")

            # Extract data from bit stream
            transform_index = int(bit_stream[i:i+2], 2) % len(self.ifs)
            r = int(bit_stream[i+2:i+10], 2)
            g = int(bit_stream[i+10:i+18], 2)
            b = int(bit_stream[i+18:i+26], 2)

            # Apply transform and create point
            transform = self.ifs[transform_index]
            new_point = self.apply_transform(transform, current_point)

            points.append(FractalPoint(
                x=new_point[0],
                y=new_point[1],
                r=r, g=g, b=b
            ))

            current_point = new_point

        if progress_callback:
            progress_callback(100, "Encryption complete")

        return {
            "original_filename": filename,
            "points": [{"x": p.x, "y": p.y, "r": p.r, "g": p.g, "b": p.b} for p in points],
            "ifs_key": [{"a": t.a, "b": t.b, "c": t.c, "d": t.d, "e": t.e, "f": t.f} for t in self.ifs],
            "metadata": {
                "version": "1.0",
                "encryption_type": "fractal_ifs",
                "original_size": len(data)
            }
        }

    def decrypt_data(self, fractal_data: Dict[str, Any],
                    progress_callback: Optional[callable] = None) -> Tuple[bytes, str]:
        """
        Decrypt fractal data back to original file.

        Args:
            fractal_data: Encrypted fractal data dictionary
            progress_callback: Optional callback for progress updates

        Returns:
            Tuple of (decrypted_bytes, original_filename)
        """
        points_data = fractal_data["points"]
        ifs_key = fractal_data.get("ifs_key", [])

        # Use provided IFS key or default
        if ifs_key:
            self.ifs = [IFSTransform(**t) for t in ifs_key]

        bit_stream = ""
        current_point = (0.0, 0.0)
        epsilon = 1e-9  # Floating point comparison tolerance

        total_points = len(points_data)

        for i, point_data in enumerate(points_data):
            if progress_callback and i % self.chunk_size == 0:
                progress = (i / total_points) * 100
                progress_callback(progress, f"Decrypting: {i}/{total_points} points")

            target_point = (point_data["x"], point_data["y"])
            found = False

            # Try each transform to find the correct one
            for j, transform in enumerate(self.ifs):
                test_point = self.apply_transform(transform, current_point)

                # Check if this transform produces the target point
                if (abs(test_point[0] - target_point[0]) < epsilon and
                    abs(test_point[1] - target_point[1]) < epsilon):

                    # Encode the data back into bit stream
                    bit_stream += format(j, '02b')  # 2 bits for transform index
                    bit_stream += format(point_data["r"], '08b')  # 8 bits for red
                    bit_stream += format(point_data["g"], '08b')  # 8 bits for green
                    bit_stream += format(point_data["b"], '08b')  # 8 bits for blue

                    found = True
                    break

            if not found:
                raise ValueError(f"Decryption failed: Could not match point {i} with any transform")

            current_point = target_point

        if progress_callback:
            progress_callback(100, "Decryption complete")

        # Convert bit stream back to bytes
        decrypted_data = self.bit_stream_to_data(bit_stream)

        # Remove padding if necessary (based on original size if available)
        original_size = fractal_data.get("metadata", {}).get("original_size")
        if original_size and len(decrypted_data) > original_size:
            decrypted_data = decrypted_data[:original_size]

        filename = fractal_data.get("original_filename", "decrypted_file")
        return decrypted_data, filename

    def create_fractal_image(self, fractal_data: Dict[str, Any],
                           width: int = 800, height: int = 800,
                           background_color: Tuple[int, int, int] = (0, 0, 0)) -> bytes:
        """
        Generate a PNG image from fractal data.

        Args:
            fractal_data: Encrypted fractal data
            width: Image width
            height: Image height
            background_color: RGB tuple for background

        Returns:
            PNG image bytes
        """
        try:
            from PIL import Image, ImageDraw
        except ImportError:
            raise ImportError("PIL (Pillow) is required for image generation. Install with: pip install Pillow")

        # Create image
        img = Image.new('RGB', (width, height), background_color)
        draw = ImageDraw.Draw(img)

        points = fractal_data["points"]

        # Find bounds of fractal
        if points:
            x_coords = [p["x"] for p in points]
            y_coords = [p["y"] for p in points]

            x_min, x_max = min(x_coords), max(x_coords)
            y_min, y_max = min(y_coords), max(y_coords)

            # Add some padding
            x_range = x_max - x_min or 1
            y_range = y_max - y_min or 1

            x_scale = (width * 0.8) / x_range
            y_scale = (height * 0.8) / y_range

            scale = min(x_scale, y_scale)
            x_offset = width/2 - (x_min + x_range/2) * scale
            y_offset = height/2 - (y_min + y_range/2) * scale

            # Draw points
            for point in points:
                x = int(point["x"] * scale + x_offset)
                y = int(point["y"] * scale + y_offset)

                if 0 <= x < width and 0 <= y < height:
                    color = (point["r"], point["g"], point["b"])
                    draw.rectangle([x, y, x+1, y+1], fill=color)

        # Save to bytes
        img_bytes = io.BytesIO()
        img.save(img_bytes, format='PNG')
        img_bytes.seek(0)
        return img_bytes.getvalue()

    def load_fractal_data(self, json_data: str) -> Dict[str, Any]:
        """Load fractal data from JSON string"""
        return json.loads(json_data)

    def save_fractal_data(self, fractal_data: Dict[str, Any]) -> str:
        """Save fractal data as JSON string"""
        return json.dumps(fractal_data, indent=2)

    def get_ifs_from_string(self, ifs_string: str) -> List[IFSTransform]:
        """Parse IFS transforms from string representation"""
        transforms = []
        lines = [line.strip() for line in ifs_string.split('\n') if line.strip()]

        for line in lines:
            if line.startswith('w') or ':' in line:
                # Parse transform parameters
                # Format: "w1: a=0.85, b=0.04, c=-0.04, d=0.85, e=0, f=1.60"
                parts = line.split(':')
                if len(parts) > 1:
                    params_str = parts[1]
                    params = {}
                    for param in params_str.split(','):
                        if '=' in param:
                            key, value = param.split('=')
                            params[key.strip()] = float(value.strip())

                    transforms.append(IFSTransform(**params))

        return transforms

    def set_ifs_key(self, transforms: List[IFSTransform]):
        """Set the IFS transforms to use as encryption key"""
        self.ifs = transforms.copy()

    def get_ifs_key(self) -> List[IFSTransform]:
        """Get current IFS transforms"""
        return self.ifs.copy()

    @classmethod
    def create_from_ifs_string(cls, ifs_string: str) -> 'FractalEncryption':
        """Create FractalEncryption instance from IFS string"""
        transforms = cls().get_ifs_from_string(ifs_string)
        return cls(transforms)
