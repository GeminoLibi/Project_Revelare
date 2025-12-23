import exifread
import datetime
from PIL import Image
from typing import Dict, Any, Optional

class MetadataExtractor:
    @staticmethod
    def extract_image_metadata(file_path: str) -> Dict[str, Any]:
        metadata = {}
        try:
            # 1. Use ExifRead for detailed EXIF tags
            with open(file_path, 'rb') as f:
                tags = exifread.process_file(f, details=False)
                
                # Extract GPS
                if 'GPS GPSLatitude' in tags and 'GPS GPSLongitude' in tags:
                    try:
                        lat_ref = str(tags.get('GPS GPSLatitudeRef', 'N'))
                        lat_vals = tags['GPS GPSLatitude'].values
                        lat = MetadataExtractor._convert_to_degrees(lat_vals)
                        if lat_ref != 'N': lat = -lat
                        
                        lon_ref = str(tags.get('GPS GPSLongitudeRef', 'E'))
                        lon_vals = tags['GPS GPSLongitude'].values
                        lon = MetadataExtractor._convert_to_degrees(lon_vals)
                        if lon_ref != 'E': lon = -lon
                        
                        metadata['GPS'] = f"{lat},{lon}"
                        metadata['GPS_Latitude'] = lat
                        metadata['GPS_Longitude'] = lon
                    except Exception:
                        pass
                
                # Extract Device Info
                if 'Image Make' in tags:
                    metadata['Make'] = str(tags['Image Make'])
                if 'Image Model' in tags:
                    metadata['Model'] = str(tags['Image Model'])
                if 'Image Software' in tags:
                    metadata['Software'] = str(tags['Image Software'])
                
                # Extract Dates
                if 'EXIF DateTimeOriginal' in tags:
                    metadata['DateTimeOriginal'] = str(tags['EXIF DateTimeOriginal'])
                elif 'Image DateTime' in tags:
                    metadata['DateTime'] = str(tags['Image DateTime'])

            # 2. Use Pillow for basic attributes
            with Image.open(file_path) as img:
                metadata['Resolution'] = f"{img.width}x{img.height}"
                metadata['Format'] = img.format
                
        except Exception:
            pass
            
        return metadata

    @staticmethod
    def _convert_to_degrees(value):
        """Helper to convert GPS coordinates to degrees"""
        d = float(value[0].num) / float(value[0].den)
        m = float(value[1].num) / float(value[1].den)
        s = float(value[2].num) / float(value[2].den)
        return d + (m / 60.0) + (s / 3600.0)

