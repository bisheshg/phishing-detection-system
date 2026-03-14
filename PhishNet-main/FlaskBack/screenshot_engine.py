"""
Screenshot Engine for Visual Similarity Detection
Uses Selenium with Chrome to capture website screenshots
Author: Bhanu Bista
Date: March 7, 2026
"""

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.core.os_manager import ChromeType
from selenium.common.exceptions import TimeoutException, WebDriverException
import time
import os
from PIL import Image
import io

class ScreenshotEngine:
    """Automated screenshot capture using Selenium Chrome"""
    
    def __init__(self, headless=True, timeout=10, chrome_binary=None):
        """
        Initialize screenshot engine

        Args:
            headless: Run browser in headless mode (no GUI)
            timeout: Page load timeout in seconds
            chrome_binary: Path to Chrome/Chromium/Brave binary (auto-detect if None)
        """
        self.timeout = timeout
        self.driver = None
        self.headless = headless
        self.chrome_binary = chrome_binary

    def _init_driver(self):
        """Initialize Chrome WebDriver with options"""
        if self.driver is not None:
            return  # Already initialized

        chrome_options = Options()

        if self.headless:
            chrome_options.add_argument('--headless=new')  # New headless mode

        # Resolve browser binary: explicit > auto-detect Brave/Chromium > let Selenium find Chrome
        binary = self.chrome_binary
        if not binary:
            for _candidate in [
                '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser',
                '/Applications/Chromium.app/Contents/MacOS/Chromium',
                '/usr/bin/brave-browser', '/usr/bin/chromium-browser', '/usr/bin/chromium',
            ]:
                if __import__('os').path.exists(_candidate):
                    binary = _candidate
                    break
        if binary:
            chrome_options.binary_location = binary

        # Performance optimizations
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-extensions')
        # NOTE: Do NOT disable images — SSIM compares logos and layout structure.
        # Disabling images makes both screenshots near-blank, causing false SSIM matches.
        # Disabling JavaScript is a better tradeoff: pages render visually (logos,
        # colours, layout intact) but phishing kit scripts don't execute.
        chrome_options.add_argument('--disable-javascript')
        # Smaller window = faster render, still large enough for meaningful SSIM
        chrome_options.add_argument('--window-size=1280,720')
        # 32MB disk cache speeds up brand database screenshot captures on repeat runs
        chrome_options.add_argument('--disk-cache-size=33554432')

        # Suppress logging
        chrome_options.add_argument('--log-level=3')
        chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])

        try:
            # Selenium 4.6+ Selenium Manager auto-downloads the correct ChromeDriver
            # for whichever binary is set (Chrome, Brave, Chromium).
            # Falls back to webdriver-manager only when Selenium Manager fails.
            is_brave = binary and 'Brave' in binary
            try:
                service = Service()  # Let Selenium Manager resolve driver automatically
                self.driver = webdriver.Chrome(service=service, options=chrome_options)
            except Exception:
                # Fallback: webdriver-manager (works for standard Chrome installs)
                driver_path = ChromeDriverManager().install()
                service = Service(driver_path)
                self.driver = webdriver.Chrome(service=service, options=chrome_options)
            self.driver.set_page_load_timeout(self.timeout)
            browser_name = 'Brave' if is_brave else 'Chrome'
            print(f"✅ {browser_name} WebDriver initialized (headless={self.headless})")
        except Exception as e:
            print(f"❌ Failed to initialize browser: {e}")
            raise
    
    def capture_screenshot(self, url, output_path=None, resize=(1280, 720)):
        """
        Capture screenshot of a URL
        
        Args:
            url: URL to screenshot
            output_path: Path to save screenshot (optional)
            resize: Resize dimensions (width, height)
        
        Returns:
            PIL Image object or None if failed
        """
        self._init_driver()
        
        try:
            print(f"📸 Capturing: {url}")
            
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            # Load page
            start_time = time.time()
            self.driver.get(url)
            
             # Wait for page to stabilize — use readyState instead of fixed sleep.
            # On dead domains Chrome shows an error page almost immediately;
            # this avoids always waiting the full 2 seconds.
            from selenium.webdriver.support.ui import WebDriverWait
            try:
                WebDriverWait(self.driver, 2).until(
                    lambda d: d.execute_script('return document.readyState') == 'complete'
                )
            except Exception:
                pass  # timeout fine — screenshot whatever rendered
            
            # Take screenshot (PNG bytes)
            screenshot_bytes = self.driver.get_screenshot_as_png()
            load_time = time.time() - start_time
            
            # Convert to PIL Image
            image = Image.open(io.BytesIO(screenshot_bytes))
            
            # Resize if specified
            if resize:
                image = image.resize(resize, Image.Resampling.LANCZOS)
            
            # Save if path provided
            if output_path:
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                image.save(output_path)
                print(f"✅ Saved: {output_path} ({load_time:.2f}s)")
            
            return image
            
        except TimeoutException:
            print(f"⏱️ Timeout loading: {url}")
            return None
        except WebDriverException as e:
            print(f"❌ WebDriver error: {url} - {str(e)[:100]}")
            return None
        except Exception as e:
            print(f"❌ Unexpected error: {url} - {e}")
            return None
    
    def capture_multiple(self, urls, output_dir='screenshots'):
        """
        Capture screenshots of multiple URLs
        
        Args:
            urls: List of URLs
            output_dir: Directory to save screenshots
        
        Returns:
            Dictionary: {url: image_object or None}
        """
        results = {}
        
        for i, url in enumerate(urls, 1):
            # Generate filename
            safe_name = url.replace('https://', '').replace('http://', '').replace('/', '_')
            safe_name = safe_name[:50]  # Limit filename length
            output_path = os.path.join(output_dir, f"{i:03d}_{safe_name}.png")
            
            # Capture
            image = self.capture_screenshot(url, output_path)
            results[url] = image
            
            print(f"Progress: {i}/{len(urls)}")
        
        return results
    
    def close(self):
        """Close the browser"""
        if self.driver:
            self.driver.quit()
            print("🚪 Browser closed")
    
    def __enter__(self):
        """Context manager entry"""
        self._init_driver()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


# Test function
def test_screenshot_engine():
    """Test the screenshot engine"""
    print("=" * 60)
    print("TESTING SCREENSHOT ENGINE")
    print("=" * 60)
    
    test_urls = [
        'https://google.com',
        'https://github.com',
        'https://example.com'
    ]
    
    with ScreenshotEngine(headless=True) as engine:
        results = engine.capture_multiple(test_urls, output_dir='test_screenshots')
        
        successful = sum(1 for img in results.values() if img is not None)
        print(f"\n✅ Success: {successful}/{len(test_urls)}")
        print(f"📁 Screenshots saved in: test_screenshots/")


if __name__ == "__main__":
    test_screenshot_engine()