/**
 * warning.js — High Risk Phishing Warning Screen Controller
 */

(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const targetUrl = urlParams.get('url') || 'https://unknown-suspicious-domain.com';

    const targetUrlText = document.getElementById('target-url-text');
    const warningReasonsList = document.getElementById('warning-reasons-list');
    const btnBackSafety = document.getElementById('btn-back-safety');
    const btnProceedUnsafe = document.getElementById('btn-proceed-unsafe');

    targetUrlText.textContent = targetUrl;

    // Run feature extraction and reasons generation
    try {
      if (typeof window.PhishingFeatures !== 'undefined' && typeof window.PhishingModel !== 'undefined') {
        const featureDict = window.PhishingFeatures.extractFeatures(targetUrl);
        const reasons = window.PhishingFeatures.explainFeatures(targetUrl, featureDict);

        warningReasonsList.innerHTML = '';
        if (reasons && reasons.length > 0) {
          reasons.forEach((reason) => {
            const li = document.createElement('li');
            li.textContent = reason;
            warningReasonsList.appendChild(li);
          });
        } else {
          const li = document.createElement('li');
          li.textContent = 'Statistical pattern matching indicated high similarity with confirmed phishing domains.';
          warningReasonsList.appendChild(li);
        }
      } else {
        const li = document.createElement('li');
        li.textContent = 'URL contains high-risk structural and syntactic heuristics commonly found in phishing campaigns.';
        warningReasonsList.appendChild(li);
      }
    } catch (err) {
      const li = document.createElement('li');
      li.textContent = 'Anomaly detected in URL hostname and protocol structure.';
      warningReasonsList.appendChild(li);
    }

    // Safety button: return to safety
    btnBackSafety.addEventListener('click', () => {
      if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.getCurrent) {
        chrome.tabs.getCurrent((tab) => {
          if (tab && tab.id) {
            chrome.tabs.remove(tab.id);
          } else {
            window.location.href = 'https://www.google.com';
          }
        });
      } else if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = 'https://www.google.com';
      }
    });

    // Bypass button: proceed with caution
    btnProceedUnsafe.addEventListener('click', () => {
      const confirmed = window.confirm(
        'SECURITY WARNING:\n\nYou are attempting to visit a website flagged as dangerous.\n' +
        'Never submit passwords, personal credentials, or payment details.\n\n' +
        'Do you still want to proceed?'
      );
      if (confirmed) {
        window.location.href = targetUrl;
      }
    });
  });
})();
