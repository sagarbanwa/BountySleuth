# Source Map Download Fix - v3.6.8

## Problem

The extension was experiencing issues downloading and processing large source maps (>50MB):

1. **Chrome**: `chrome.tabs.sendMessage` has a message size limit of ~64MB, causing failures for large sourcemaps
2. **Firefox**: `browser.tabs.sendMessage` has a stricter limit of ~50MB, failing even earlier

When trying to download large sourcemaps, the extension would fail silently or throw errors because the entire file content was being sent through a single message channel.

## Solution

Implemented **chunked transfer with robust error handling** for large source maps in both Chrome and Firefox extensions:

### Key Changes

#### 1. Content Script (content.js) - Both Browsers

- Added detection for large files (>40MB threshold)
- When a large file is detected, returns metadata instead of content:
  ```javascript
  {
    chunked: true,
    totalSize: <file_size>,
    totalChunks: <number_of_chunks>
  }
  ```
- Added new message handler `fetchSourceMapChunk` that fetches specific chunks
- Each chunk is 40MB (safe for both browsers)
- **Error Handling**:
  - Tries HTTP Range requests first (most efficient)
  - Falls back to full fetch + slice if Range not supported
  - Multiple credential strategies (include, omit, default)
  - Validates chunk extraction with size checks
  - Returns detailed error messages for debugging

#### 2. Background Script (background.js) - Both Browsers

- Modified Strategy 4 (Chrome) and Strategy 5 (Firefox) to handle chunked transfers
- First request checks if file needs chunking
- If chunked, iterates through all chunks sequentially
- **Robust Error Recovery**:
  - **Automatic Retry**: Each chunk retries up to 3 times on failure
  - **Exponential Backoff**: Retry delays increase (1s, 2s, 3s)
  - **Missing Chunk Detection**: Verifies all chunks received before reassembly
  - **Size Validation**: Compares final size with expected size
  - **Detailed Logging**: Shows retry attempts and failure reasons
- Reassembles chunks into complete file before processing
- Maintains backward compatibility with small files (<40MB)

### Error Handling Features

#### Chunk-Level Failures
```javascript
// If a chunk fails, it will:
1. Log the error
2. Wait (1s * retry_count)
3. Retry up to 3 times
4. If all retries fail, throw detailed error
```

#### Network Issues
- Handles timeouts (60s Chrome, 30s Firefox per chunk)
- Handles connection drops
- Handles CORS issues with multiple credential strategies

#### Data Integrity
- Verifies all chunks are non-null/undefined
- Checks final size matches expected size
- Logs warnings for size mismatches (but continues)

#### User Feedback
Console logs show:
- "Fetching chunk X / Y" - Progress
- "(retry 1/3)" - Retry attempts
- "Chunk X failed: [reason]" - Specific errors
- "Missing chunks: [list]" - Which chunks failed
- "Size mismatch! Expected: X Got: Y" - Data integrity issues

### Technical Details

**Chunk Size**: 40MB
- Safe for both Chrome (64MB limit) and Firefox (50MB limit)
- Provides buffer for message overhead

**Retry Strategy**:
- Max retries: 3 per chunk
- Delay: 1s, 2s, 3s (exponential backoff)
- Only retries on transient errors (network, timeout)
- Fails fast on permanent errors (404, 403)

**Fallback Strategy**:
1. Try HTTP Range request (efficient, only downloads needed chunk)
2. If Range not supported, fetch full file and slice in memory
3. Each chunk is sent separately through message channel
4. If chunk fails, retry with exponential backoff
5. If all retries fail, entire operation fails with detailed error

**Progress Logging**:
- Console logs show chunk progress: "Fetching chunk X / Y"
- Shows retry attempts: "(retry 2/3)"
- Shows fetch method: "(via Range)" or "(via slice)"
- Helps debug large file downloads

## Benefits

1. ✅ **No Size Limit**: Can now handle source maps of any size
2. ✅ **Memory Efficient**: Only one chunk in memory at a time during transfer
3. ✅ **Robust Error Recovery**: Automatic retries with exponential backoff
4. ✅ **Data Integrity**: Validates all chunks and final size
5. ✅ **Backward Compatible**: Small files (<40MB) work exactly as before
6. ✅ **Cross-Browser**: Works identically in Chrome and Firefox
7. ✅ **Resilient**: Handles network issues, timeouts, and transient failures
8. ✅ **Debuggable**: Detailed console logging for troubleshooting

## Error Scenarios Handled

| Scenario | Handling |
|----------|----------|
| Network timeout | Retry up to 3 times with backoff |
| Connection drop | Retry up to 3 times with backoff |
| Chunk corruption | Detected via size validation |
| Missing chunks | Detected before reassembly, fails with list |
| Size mismatch | Logged as warning, continues processing |
| HTTP errors (4xx/5xx) | Fails immediately with error code |
| CORS issues | Multiple credential strategies |
| Range not supported | Falls back to full fetch + slice |

## Testing

To test with large source maps:

1. Find a website with large bundled JS (e.g., modern React/Angular apps)
2. Open BountySleuth extension
3. Navigate to "Source Map Detector" section
4. Click "🔓 Unpack & Download" on a large source map (>50MB)
5. Check browser console for chunk progress logs
6. Verify ZIP file downloads successfully with all source files

To test error recovery:
1. Use browser DevTools Network tab to throttle connection
2. Try unpacking a large source map
3. Watch console for retry attempts
4. Verify successful completion despite network issues

## Files Modified

- `chrome_bounty_extension/content.js` - Added chunked transfer with error handling
- `chrome_bounty_extension/background.js` - Added chunk reassembly with retry logic
- `firefox_bounty_extension/content.js` - Added chunked transfer with error handling
- `firefox_bounty_extension/background.js` - Added chunk reassembly with retry logic

## Version

This fix is included in **BountySleuth v3.6.8**
