// Lightweight content script for telemetry & client protection
(function () {
  let fingerprintAttempts = 0;

  // Intercept canvas toDataURL or getImageData probes
  try {
    const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function (...args) {
      fingerprintAttempts++;
      return originalToDataURL.apply(this, args);
    };

    const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function (...args) {
      fingerprintAttempts++;
      return originalGetImageData.apply(this, args);
    };
  } catch (e) {
    // Fail gracefully
  }
})();
