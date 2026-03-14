"""
SSIM (Structural Similarity Index) Analyzer
Compares screenshots to detect visual clones
Author: Bhanu Bista
Date: March 7, 2026
"""

from skimage.metrics import structural_similarity as ssim
from skimage import io, transform
import numpy as np
from PIL import Image
import cv2
import matplotlib.pyplot as plt
import os

class SSIMAnalyzer:
    """Analyze visual similarity between images using SSIM"""
    
    def __init__(self, threshold=0.85):
        """
        Initialize SSIM analyzer
        
        Args:
            threshold: SSIM score above which images are considered clones (0-1)
        """
        self.threshold = threshold
    
    def load_and_prepare(self, image_path_or_obj, target_size=(1280, 720)):
        """
        Load and prepare image for SSIM comparison
        
        Args:
            image_path_or_obj: Path to image or PIL Image object
            target_size: Resize to this size for comparison
        
        Returns:
            Grayscale numpy array
        """
        # Load image
        if isinstance(image_path_or_obj, str):
            image = Image.open(image_path_or_obj)
        elif isinstance(image_path_or_obj, Image.Image):
            image = image_path_or_obj
        else:
            raise ValueError("Input must be file path or PIL Image")
        
        # Resize to standard size
        if image.size != target_size:
            image = image.resize(target_size, Image.Resampling.LANCZOS)
        
        # Convert to grayscale numpy array
        gray = np.array(image.convert('L'))
        
        return gray
    
    def calculate_ssim(self, image1, image2):
        """
        Calculate SSIM score between two images
        
        Args:
            image1: First image (path or PIL Image)
            image2: Second image (path or PIL Image)
        
        Returns:
            dict with score, is_clone, and diff_image
        """
        # Prepare images
        img1_gray = self.load_and_prepare(image1)
        img2_gray = self.load_and_prepare(image2)
        
        # Calculate SSIM
        score, diff = ssim(img1_gray, img2_gray, full=True)
        
        # Convert difference image to 0-255 range
        diff = (diff * 255).astype("uint8")
        
        # Determine if clone
        is_clone = score >= self.threshold
        
        return {
            'ssim_score': float(score),
            'is_clone': is_clone,
            'threshold': self.threshold,
            'confidence': 'HIGH' if abs(score - self.threshold) > 0.1 else 'MEDIUM',
            'diff_image': diff
        }
    
    def generate_heatmap(self, image1, image2, output_path=None):
        """
        Generate visual heatmap showing differences
        
        Args:
            image1: First image
            image2: Second image
            output_path: Where to save heatmap (optional)
        
        Returns:
            Path to saved heatmap or None
        """
        result = self.calculate_ssim(image1, image2)
        diff = result['diff_image']
        
        # Create colorized heatmap (red = different, green = similar)
        # Invert so differences show in red
        heatmap = cv2.applyColorMap(255 - diff, cv2.COLORMAP_JET)
        
        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            cv2.imwrite(output_path, heatmap)
            print(f"HEATMAP SAVED: {output_path}")
            return output_path
        
        return heatmap
    
    def generate_comparison_report(self, image1, image2, name1="Image 1", name2="Image 2", output_path=None):
        """
        Generate side-by-side comparison with SSIM score
        
        Args:
            image1: First image
            image2: Second image  
            name1: Label for first image
            name2: Label for second image
            output_path: Where to save report
        
        Returns:
            Path to saved report
        """
        # Calculate SSIM
        result = self.calculate_ssim(image1, image2)
        score = result['ssim_score']
        is_clone = result['is_clone']
        
        # Load images for display
        img1_display = self.load_and_prepare(image1)
        img2_display = self.load_and_prepare(image2)
        diff_map = result['diff_image']
        
        # Create figure with 3 subplots
        fig, axes = plt.subplots(1, 3, figsize=(18, 6))
        
        # Image 1
        axes[0].imshow(img1_display, cmap='gray')
        axes[0].set_title(f'{name1}', fontsize=14, fontweight='bold')
        axes[0].axis('off')
        
        # Image 2
        axes[1].imshow(img2_display, cmap='gray')
        axes[1].set_title(f'{name2}', fontsize=14, fontweight='bold')
        axes[1].axis('off')
        
        # Difference heatmap
        axes[2].imshow(255 - diff_map, cmap='RdYlGn', vmin=0, vmax=255)
        axes[2].set_title('Similarity Map\n(Green=Similar, Red=Different)', fontsize=12)
        axes[2].axis('off')
        
        # Overall title with score
        status = "WARNING: VISUAL CLONE DETECTED" if is_clone else "OK: Different Sites"
        color = 'red' if is_clone else 'green'
        
        fig.suptitle(
            f'{status}\nSSIM Score: {score:.4f} (Threshold: {self.threshold})',
            fontsize=16,
            fontweight='bold',
            color=color
        )
        
        plt.tight_layout()
        
        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            print(f"COMPARISON REPORT SAVED: {output_path}")
            plt.close()
            return output_path
        else:
            plt.show()
            return None
    
    def compare_batch(self, image_pairs, output_dir='comparisons'):
        """
        Compare multiple pairs of images
        
        Args:
            image_pairs: List of tuples [(img1, img2, name1, name2), ...]
            output_dir: Directory to save reports
        
        Returns:
            List of results
        """
        results = []
        
        for i, (img1, img2, name1, name2) in enumerate(image_pairs, 1):
            print(f"\n[{i}/{len(image_pairs)}] Comparing: {name1} vs {name2}")
            
            result = self.calculate_ssim(img1, img2)
            result['name1'] = name1
            result['name2'] = name2
            
            # Generate report
            report_path = os.path.join(output_dir, f'comparison_{i:03d}.png')
            self.generate_comparison_report(img1, img2, name1, name2, report_path)
            
            result['report_path'] = report_path
            results.append(result)
            
            print(f"   SSIM: {result['ssim_score']:.4f} | Clone: {result['is_clone']}")
        
        return results


# Test function
def test_ssim_analyzer():
    """Test the SSIM analyzer"""
    print("=" * 60)
    print("TESTING SSIM ANALYZER")
    print("=" * 60)
    
    # Check if test screenshots exist
    test_dir = 'test_screenshots'
    if not os.path.exists(test_dir):
        print(f"ERROR: Test screenshots not found. Run screenshot_engine.py first!")
        return
    
    screenshots = sorted([f for f in os.listdir(test_dir) if f.endswith('.png')])
    
    if len(screenshots) < 2:
        print(f"ERROR: Need at least 2 screenshots to compare")
        return
    
    print(f"FOUND {len(screenshots)} test screenshots")
    
    # Test comparison
    analyzer = SSIMAnalyzer(threshold=0.85)
    
    # Compare first two screenshots
    img1_path = os.path.join(test_dir, screenshots[0])
    img2_path = os.path.join(test_dir, screenshots[1])
    
    print(f"\nComparing:")
    print(f"  Image 1: {screenshots[0]}")
    print(f"  Image 2: {screenshots[1]}")
    
    result = analyzer.calculate_ssim(img1_path, img2_path)
    
    print(f"\n{'='*60}")
    print(f"SSIM Score: {result['ssim_score']:.4f}")
    print(f"Threshold: {result['threshold']}")
    print(f"Is Clone?: {result['is_clone']}")
    print(f"Confidence: {result['confidence']}")
    print(f"{'='*60}")
    
    # Generate comparison report with proper path
    report_path = os.path.join(test_dir, 'test_comparison_report.png')
    analyzer.generate_comparison_report(
        img1_path, img2_path,
        screenshots[0], screenshots[1],
        report_path
    )
    
    print(f"\nTEST COMPLETE! Check {report_path}")


if __name__ == "__main__":
    test_ssim_analyzer()