/**
 * model.js
 * In-browser inference engine for Logistic Regression URL classification.
 * Performs 100% client-side prediction without external servers.
 */

(function (global) {
  'use strict';

  // Exported Model Parameters
  const MODEL_PARAMS = {
  "model_type": "LogisticRegression",
  "description": "AI-Powered Phishing Website Detector URL Classifier",
  "exported_at": "2026-10-16T16:31:37.686345+00:00",
  "feature_names": [
    "url_length",
    "hostname_length",
    "dot_count",
    "hyphen_count",
    "subdomain_count",
    "has_ip",
    "has_https",
    "has_suspicious_keyword",
    "has_at_symbol",
    "digits_in_hostname"
  ],
  "weights": [
    0.0350089842286627,
    0.07612565615052896,
    0.04842665980017256,
    0.2222152605909115,
    -0.8776203582493376,
    0.0038555958908805636,
    -7.739232033730265,
    2.987725484110923,
    0.14288729641812314,
    0.7897243871762151
  ],
  "intercept": 3.292919128930012,
  "coefficients_dict": {
    "url_length": 0.035009,
    "hostname_length": 0.076126,
    "dot_count": 0.048427,
    "hyphen_count": 0.222215,
    "subdomain_count": -0.87762,
    "has_ip": 0.003856,
    "has_https": -7.739232,
    "has_suspicious_keyword": 2.987725,
    "has_at_symbol": 0.142887,
    "digits_in_hostname": 0.789724
  },
  "classification_thresholds": {
    "legitimate_below": 0.35,
    "suspicious_range": [
      0.35,
      0.7
    ],
    "phishing_above": 0.7
  },
  "performance_metrics": {
    "accuracy": 0.9361,
    "precision": 0.9802,
    "recall": 0.8902,
    "f1_score": 0.9331,
    "roc_auc": 0.9657
  }
};

  /**
   * Sigmoid activation function: 1 / (1 + e^-z)
   */
  function sigmoid(z) {
    if (z < -45.0) return 0.0;
    if (z > 45.0) return 1.0;
    return 1.0 / (1.0 + Math.exp(-z));
  }

  /**
   * Evaluates the linear model: logit = intercept + sum(weight_i * feature_i)
   * Returns calibrated phishing probability in [0, 1].
   */
  function predictProbability(featuresVector) {
    if (!featuresVector || featuresVector.length !== MODEL_PARAMS.feature_names.length) {
      throw new Error(
        `Feature vector length mismatch: expected ${MODEL_PARAMS.feature_names.length}, got ${featuresVector ? featuresVector.length : 0}`
      );
    }

    let logit = MODEL_PARAMS.intercept;
    for (let i = 0; i < featuresVector.length; i++) {
      logit += MODEL_PARAMS.weights[i] * featuresVector[i];
    }

    return sigmoid(logit);
  }

  /**
   * Categorizes probability into Legitimate, Suspicious, or Phishing.
   */
  function classifyProbability(prob) {
    const thresholds = MODEL_PARAMS.classification_thresholds;
    if (prob < thresholds.legitimate_below) {
      return {
        category: 'Legitimate',
        riskLevel: 'low',
        color: '#10b981', // green
        probability: prob,
        headline: 'Website Appears Legitimate'
      };
    } else if (prob < thresholds.suspicious_range[1]) {
      return {
        category: 'Suspicious',
        riskLevel: 'medium',
        color: '#f59e0b', // amber
        probability: prob,
        headline: 'Suspicious Elements Detected'
      };
    } else {
      return {
        category: 'Phishing',
        riskLevel: 'high',
        color: '#ef4444', // red
        probability: prob,
        headline: 'High Phishing Risk'
      };
    }
  }

  /**
   * End-to-end classification for a URL string.
   */
  function predictUrl(urlStr, featuresExtractor) {
    if (!urlStr || typeof urlStr !== 'string' || !urlStr.trim()) {
      throw new Error('Please enter a valid URL.');
    }

    const extractor = featuresExtractor || (global.PhishingFeatures && global.PhishingFeatures.extractFeaturesVector);
    const explainer = (global.PhishingFeatures && global.PhishingFeatures.explainFeatures);

    if (!extractor) {
      throw new Error('Feature extractor module (features.js) not loaded.');
    }

    const featureVector = extractor(urlStr);
    const prob = predictProbability(featureVector);
    const result = classifyProbability(prob);

    // Attach explanations
    if (explainer) {
      const featureDict = global.PhishingFeatures.extractFeatures(urlStr);
      result.reasons = explainer(urlStr, featureDict);
      result.features = featureDict;
    } else {
      result.reasons = ['Heuristic analysis completed.'];
      result.features = {};
    }

    result.url = urlStr;
    return result;
  }

  const api = {
    MODEL_PARAMS,
    sigmoid,
    predictProbability,
    classifyProbability,
    predictUrl
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  if (typeof global !== 'undefined') {
    global.PhishingModel = api;
  }
})(typeof window !== 'undefined' ? window : globalThis);
