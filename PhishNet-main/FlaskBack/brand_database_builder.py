"""
Brand Database Builder
Captures legitimate brand screenshots for visual comparison
"""

from screenshot_engine import ScreenshotEngine
import json
import os
from datetime import datetime

# Top phishing targets (APWG data)
BRANDS = [
    {"name": "PayPal", "url": "https://www.paypal.com"},
    {"name": "Google", "url": "https://www.google.com"},
    {"name": "Facebook", "url": "https://www.facebook.com"},
    {"name": "Microsoft", "url": "https://www.microsoft.com"},
    {"name": "Amazon", "url": "https://www.amazon.com"},
    {"name": "Apple", "url": "https://www.apple.com"},
    {"name": "Instagram", "url": "https://www.instagram.com"},
    {"name": "LinkedIn", "url": "https://www.linkedin.com"},
    {"name": "Netflix", "url": "https://www.netflix.com"},
    {"name": "Chase", "url": "https://www.chase.com"},
    {"name": "esewa", "url": "https://esewa.com.np"},
]

def build_database(output_dir='brand_database'):
    """Capture all brand screenshots and create metadata"""
    
    screenshots_dir = os.path.join(output_dir, 'screenshots')
    os.makedirs(screenshots_dir, exist_ok=True)
    
    metadata = []
    
    print(f"Building brand database: {len(BRANDS)} brands")
    print("="*60)
    
    with ScreenshotEngine(headless=True) as engine:
        for i, brand in enumerate(BRANDS, 1):
            print(f"\n[{i}/{len(BRANDS)}] Capturing {brand['name']}...")
            
            filename = f"{brand['name'].lower().replace(' ', '_')}.png"
            filepath = os.path.join(screenshots_dir, filename)
            
            img = engine.capture_screenshot(brand['url'], filepath)
            
            metadata.append({
                "brand_name": brand['name'],
                "url": brand['url'],
                "screenshot_file": filename,
                "capture_date": datetime.now().isoformat(),
                "success": img is not None
            })
    
    # Save metadata
    metadata_path = os.path.join(output_dir, 'metadata.json')
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    successful = sum(1 for m in metadata if m['success'])
    print(f"\n{'='*60}")
    print(f"DATABASE COMPLETE: {successful}/{len(BRANDS)} brands captured")
    print(f"Location: {output_dir}/")
    print(f"Metadata: {metadata_path}")

if __name__ == "__main__":
    build_database()