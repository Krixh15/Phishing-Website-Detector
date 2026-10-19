/**
 * popup.js — AI Phishing Website Detector Chrome Extension
 * Coordinates user interaction, URL validation, feature extraction, and ML classification.
 */

(function () {
  'use strict';

  // DOM Elements
  const urlForm = document.getElementById('url-form');
  const urlInput = document.getElementById('url-input');
  const btnClear = document.getElementById('btn-clear-input');
  const btnScanCurrent = document.getElementById('btn-scan-current');
  const btnScanAnother = document.getElementById('btn-scan-another');
  const btnOpenWarning = document.getElementById('btn-open-warning');
  const btnDismissError = document.getElementById('btn-dismiss-error');
  const btnToggleFeatures = document.getElementById('btn-toggle-features');
  const featuresTableContainer = document.getElementById('features-table-container');
  const accordionArrow = document.getElementById('accordion-arrow');

  const loadingState = document.getElementById('loading-state');
  const errorState = document.getElementById('error-state');
  const errorTitle = document.getElementById('error-title');
  const errorMessage = document.getElementById('error-message');
  const resultState = document.getElementById('result-state');

  const statusCard = document.getElementById('status-card');
  const riskBadge = document.getElementById('risk-badge');
  const resultHeadline = document.getElementById('result-headline');
  const scannedUrlDisplay = document.getElementById('scanned-url-display');
  const riskPercent = document.getElementById('risk-percent');
  const meterFill = document.getElementById('meter-fill');
  const reasonsList = document.getElementById('reasons-list');
  const highRiskAlert = document.getElementById('high-risk-alert');
  const featuresTableBody = document.getElementById('features-table-body');

  let currentScannedUrl = '';

  // Feature descriptive names for the inspector table
  const FEATURE_DISPLAY_NAMES = {
    url_length: 'Total URL Length',
    hostname_length: 'Hostname Length',
    dot_count: 'Dot Count (.)',
    hyphen_count: 'Hyphen Count (-)',
    subdomain_count: 'Subdomain Count',
    has_ip: 'IP Address in Host',
    has_https: 'Uses HTTPS Protocol',
    has_suspicious_keyword: 'Suspicious Keywords',
    has_at_symbol: 'At Symbol (@)',
    digits_in_hostname: 'Digits in Hostname'
  };

  /**
   * Initializes event listeners and automatically scans current tab if available.
   */
  document.addEventListener('DOMContentLoaded', () => {
    bindEvents();
    autoScanActiveTab();
  });

  function bindEvents() {
    urlForm.addEventListener('submit', handleFormSubmit);

    urlInput.addEventListener('input', () => {
      btnClear.classList.toggle('hidden', urlInput.value.length === 0);
    });

    btnClear.addEventListener('click', () => {
      urlInput.value = '';
      btnClear.classList.add('hidden');
      urlInput.focus();
    });

    btnScanCurrent.addEventListener('click', scanCurrentTab);

    btnScanAnother.addEventListener('click', () => {
      resultState.classList.add('hidden');
      errorState.classList.add('hidden');
      urlInput.value = '';
      btnClear.classList.add('hidden');
      urlInput.focus();
    });

    btnDismissError.addEventListener('click', () => {
      errorState.classList.add('hidden');
    });

    btnToggleFeatures.addEventListener('click', toggleFeaturesAccordion);

    btnOpenWarning.addEventListener('click', () => {
      if (!currentScannedUrl) return;
      const warningUrl = chrome.runtime.getURL(`warning.html?url=${encodeURIComponent(currentScannedUrl)}`);
      chrome.tabs.create({ url: warningUrl });
    });
  }

  /**
   * Attempts to automatically pre-scan the active tab on popup opening.
   */
  function autoScanActiveTab() {
    if (typeof chrome === 'undefined' || !chrome.tabs || !chrome.tabs.query) {
      return;
    }

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (chrome.runtime.lastError || !tabs || tabs.length === 0) return;
      const activeTab = tabs[0];
      if (activeTab && activeTab.url && isAnalyzableUrl(activeTab.url)) {
        urlInput.value = activeTab.url;
        btnClear.classList.remove('hidden');
        processUrlAnalysis(activeTab.url);
      }
    });
  }

  /**
   * Triggered when user clicks "Scan Current Tab".
   */
  function scanCurrentTab() {
    if (typeof chrome === 'undefined' || !chrome.tabs || !chrome.tabs.query) {
      showError('Browser API Unavailable', 'Chrome tabs API is not accessible in this environment.');
      return;
    }

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (chrome.runtime.lastError || !tabs || tabs.length === 0) {
        showError('Tab Access Error', 'Unable to retrieve the active browser tab.');
        return;
      }

      const activeUrl = tabs[0].url || '';
      if (!activeUrl) {
        showError('No URL Found', 'The current tab does not have an active URL.');
        return;
      }

      urlInput.value = activeUrl;
      btnClear.classList.remove('hidden');
      processUrlAnalysis(activeUrl);
    });
  }

  /**
   * Form submit handler.
   */
  function handleFormSubmit(e) {
    e.preventDefault();
    const rawInput = urlInput.value.trim();
    if (!rawInput) {
      showError('Missing URL', 'Please enter a website URL to analyze.');
      return;
    }
    processUrlAnalysis(rawInput);
  }

  /**
   * Validates and normalizes URL string.
   */
  function validateAndNormalizeUrl(inputStr) {
    let clean = inputStr.trim();

    // Check for internal browser URLs
    if (/^(chrome|edge|brave|opera|about|view-source|chrome-extension):/i.test(clean)) {
      throw new Error('Internal browser pages (chrome://, about:, extensions) cannot be scanned for phishing.');
    }

    // Check for javascript or data schemes
    if (/^(javascript|data|file):/i.test(clean)) {
      throw new Error('Special schemes (javascript:, data:, file:) are not valid web targets.');
    }

    // Prepend http:// if user entered bare domain or IP
    if (!/^https?:\/\//i.test(clean)) {
      clean = 'http://' + clean;
    }

    try {
      const parsed = new URL(clean);
      if (!parsed.hostname || parsed.hostname.indexOf('.') === -1 && !/^\d+\.\d+\.\d+\.\d+$/.test(parsed.hostname) && parsed.hostname !== 'localhost') {
        throw new Error('The URL hostname must be a valid domain name or IPv4 address.');
      }
      return clean;
    } catch (err) {
      throw new Error('Please enter a well-formed web URL (e.g., https://example.com).');
    }
  }

  /**
   * Checks if URL is valid for automated scan.
   */
  function isAnalyzableUrl(urlStr) {
    if (!urlStr) return false;
    return /^https?:\/\//i.test(urlStr);
  }

  /**
   * Executes feature extraction and ML classification.
   */
  function processUrlAnalysis(rawUrl) {
    errorState.classList.add('hidden');
    resultState.classList.add('hidden');
    loadingState.classList.remove('hidden');

    let normalizedUrl;
    try {
      normalizedUrl = validateAndNormalizeUrl(rawUrl);
    } catch (err) {
      loadingState.classList.add('hidden');
      showError('Validation Error', err.message);
      return;
    }

    // Check model availability
    if (typeof window.PhishingModel === 'undefined' || typeof window.PhishingFeatures === 'undefined') {
      loadingState.classList.add('hidden');
      showError('Model Offline', 'The client-side machine learning engine could not be loaded.');
      return;
    }

    // Brief timeout to let the DOM show the loading state cleanly
    setTimeout(() => {
      try {
        const prediction = window.PhishingModel.predictUrl(normalizedUrl);
        currentScannedUrl = normalizedUrl;
        renderResults(prediction);
      } catch (err) {
        showError('Analysis Failure', err.message || 'An error occurred during inference.');
      } finally {
        loadingState.classList.add('hidden');
      }
    }, 120);
  }

  /**
   * Renders prediction output to the popup interface.
   */
  function renderResults(prediction) {
    const { category, riskLevel, color, probability, headline, reasons, features, url } = prediction;

    // Headline and URL
    resultHeadline.textContent = headline;
    scannedUrlDisplay.textContent = url;
    scannedUrlDisplay.title = url;

    // Badges & Status Card Styling
    statusCard.className = `status-card status-${category.toLowerCase()}`;
    riskBadge.className = `risk-badge badge-${category.toLowerCase()}`;
    riskBadge.textContent = category;

    // Meter Fill & Percentage
    const pct = (probability * 100).toFixed(1);
    riskPercent.textContent = `${pct}%`;
    riskPercent.style.color = color;

    meterFill.style.width = `${Math.min(100, Math.max(2, pct))}%`;
    meterFill.style.backgroundColor = color;

    // Reasons List
    reasonsList.innerHTML = '';
    if (reasons && reasons.length > 0) {
      reasons.forEach((reason) => {
        const li = document.createElement('li');
        li.textContent = reason;
        reasonsList.appendChild(li);
      });
    } else {
      const li = document.createElement('li');
      li.textContent = 'No high-risk URL indicators detected.';
      reasonsList.appendChild(li);
    }

    // High Risk Warning Action
    if (category === 'Phishing') {
      highRiskAlert.classList.remove('hidden');
    } else {
      highRiskAlert.classList.add('hidden');
    }

    // Populate Features Table
    populateFeaturesTable(features);

    // Reveal Result
    resultState.classList.remove('hidden');
  }

  /**
   * Builds the inspection table for all 10 features.
   */
  function populateFeaturesTable(features) {
    featuresTableBody.innerHTML = '';
    if (!features) return;

    const weights = window.PhishingModel.MODEL_PARAMS.coefficients_dict || {};

    Object.keys(FEATURE_DISPLAY_NAMES).forEach((key) => {
      const row = document.createElement('tr');

      const nameCell = document.createElement('td');
      nameCell.textContent = FEATURE_DISPLAY_NAMES[key] || key;

      const valCell = document.createElement('td');
      const valSpan = document.createElement('span');
      valSpan.className = 'val-badge';
      let val = features[key];
      if (typeof val === 'boolean') {
        valSpan.textContent = val ? '1 (Yes)' : '0 (No)';
      } else {
        valSpan.textContent = String(val);
      }
      valCell.appendChild(valSpan);

      const impactCell = document.createElement('td');
      const weight = weights[key] !== undefined ? weights[key] : 0;
      if (key === 'has_https') {
        if (features[key] === 1) {
          impactCell.className = 'impact-neg';
          impactCell.textContent = 'Protective (HTTPS)';
        } else {
          impactCell.className = 'impact-pos';
          impactCell.textContent = 'Increases Risk (HTTP)';
        }
      } else if (weight > 0 && features[key] > 0) {
        impactCell.className = 'impact-pos';
        impactCell.textContent = `+${weight.toFixed(2)} (Risk)`;
      } else if (weight < 0 && features[key] > 0) {
        impactCell.className = 'impact-neg';
        impactCell.textContent = `${weight.toFixed(2)} (Safe)`;
      } else {
        impactCell.className = 'impact-neutral';
        impactCell.textContent = 'Neutral';
      }

      row.appendChild(nameCell);
      row.appendChild(valCell);
      row.appendChild(impactCell);
      featuresTableBody.appendChild(row);
    });
  }

  /**
   * Toggles collapsible feature inspector table.
   */
  function toggleFeaturesAccordion() {
    const isHidden = featuresTableContainer.classList.contains('hidden');
    if (isHidden) {
      featuresTableContainer.classList.remove('hidden');
      accordionArrow.textContent = '▲';
    } else {
      featuresTableContainer.classList.add('hidden');
      accordionArrow.textContent = '▼';
    }
  }

  /**
   * Shows error feedback card.
   */
  function showError(title, msg) {
    errorTitle.textContent = title;
    errorMessage.textContent = msg;
    errorState.classList.remove('hidden');
  }

})();
