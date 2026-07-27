document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const passwordInput = document.getElementById('passwordInput');
  const toggleVisibilityBtn = document.getElementById('toggleVisibilityBtn');
  const eyeIcon = document.getElementById('eyeIcon');
  const eyeOffIcon = document.getElementById('eyeOffIcon');
  const clearInputBtn = document.getElementById('clearInputBtn');
  
  const progressBar = document.getElementById('progressBar');
  const entropyReadout = document.getElementById('entropyReadout');
  const strengthLabel = document.getElementById('strengthLabel');
  const liveStatusText = document.getElementById('liveStatusText');

  const entropyValue = document.getElementById('entropyValue');
  const strengthBadge = document.getElementById('strengthBadge');

  const poolSizeValue = document.getElementById('poolSizeValue');
  const poolSizeBadge = document.getElementById('poolSizeBadge');
  const tagLower = document.getElementById('tagLower');
  const tagUpper = document.getElementById('tagUpper');
  const tagDigits = document.getElementById('tagDigits');
  const tagSymbols = document.getElementById('tagSymbols');

  const breachBadgeContainer = document.getElementById('breachBadgeContainer');
  const breachDetailText = document.getElementById('breachDetailText');
  const sha1PrefixText = document.getElementById('sha1PrefixText');

  const crackTimeValue = document.getElementById('crackTimeValue');
  const recommendationList = document.getElementById('recommendationList');

  const themeToggleBtn = document.getElementById('themeToggleBtn');
  const sunIcon = document.getElementById('sunIcon');
  const moonIcon = document.getElementById('moonIcon');
  const themeLabel = document.getElementById('themeLabel');

  const toggleExplanationHeader = document.getElementById('toggleExplanationHeader');
  const explanationBody = document.getElementById('explanationBody');
  const toggleExpBtn = document.getElementById('toggleExpBtn');

  let debounceTimer = null;

  // --- Theme Toggle Handler ---
  function initTheme() {
    const savedTheme = localStorage.getItem('keyguard_theme') || 'dark';
    if (savedTheme === 'light') {
      document.documentElement.classList.remove('dark');
      sunIcon.classList.remove('hidden');
      moonIcon.classList.add('hidden');
      themeLabel.textContent = 'Light Mode';
    } else {
      document.documentElement.classList.add('dark');
      sunIcon.classList.add('hidden');
      moonIcon.classList.remove('hidden');
      themeLabel.textContent = 'Dark Mode';
    }
  }

  themeToggleBtn.addEventListener('click', () => {
    const isDark = document.documentElement.classList.contains('dark');
    if (isDark) {
      document.documentElement.classList.remove('dark');
      localStorage.setItem('keyguard_theme', 'light');
      sunIcon.classList.remove('hidden');
      moonIcon.classList.add('hidden');
      themeLabel.textContent = 'Light Mode';
    } else {
      document.documentElement.classList.add('dark');
      localStorage.setItem('keyguard_theme', 'dark');
      sunIcon.classList.add('hidden');
      moonIcon.classList.remove('hidden');
      themeLabel.textContent = 'Dark Mode';
    }
  });

  initTheme();

  // --- Password Visibility Toggle ---
  toggleVisibilityBtn.addEventListener('click', () => {
    const isPassword = passwordInput.type === 'password';
    passwordInput.type = isPassword ? 'text' : 'password';
    eyeIcon.classList.toggle('hidden', isPassword);
    eyeOffIcon.classList.toggle('hidden', !isPassword);
  });

  // --- Clear Input Button ---
  clearInputBtn.addEventListener('click', () => {
    passwordInput.value = '';
    clearInputBtn.classList.add('hidden');
    handleInputChange();
    passwordInput.focus();
  });

  // --- Explanation Collapse Toggle ---
  toggleExplanationHeader.addEventListener('click', () => {
    const isHidden = explanationBody.classList.contains('hidden');
    explanationBody.classList.toggle('hidden', !isHidden);
    toggleExpBtn.textContent = isHidden ? '[-] Collapse' : '[+] Expand';
  });

  // --- Input Event Listener ---
  passwordInput.addEventListener('input', () => {
    const hasValue = passwordInput.value.length > 0;
    clearInputBtn.classList.toggle('hidden', !hasValue);
    
    // 1. Instant client-side mathematical evaluation for immediate response
    updateInstantClientEvaluation(passwordInput.value);

    // 2. Debounced backend full audit (includes HIBP k-Anonymity)
    clearTimeout(debounceTimer);
    if (hasValue) {
      liveStatusText.textContent = 'Auditing breach database...';
      debounceTimer = setTimeout(() => {
        fetchBackendAudit(passwordInput.value);
      }, 300);
    } else {
      resetDashboard();
    }
  });

  function handleInputChange() {
    passwordInput.dispatchEvent(new Event('input'));
  }

  // --- Instant Client-Side Evaluation ---
  function updateInstantClientEvaluation(password) {
    if (!password) {
      resetDashboard();
      return;
    }

    const length = password.length;
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasDigits = /\d/.test(password);
    const hasSymbols = /[^a-zA-Z0-9]/.test(password);

    let poolSize = 0;
    if (hasLower) poolSize += 26;
    if (hasUpper) poolSize += 26;
    if (hasDigits) poolSize += 10;
    if (hasSymbols) poolSize += 32;

    const entropy = poolSize > 0 ? (length * Math.log2(poolSize)).toFixed(1) : (0.0).toFixed(1);
    const entropyNum = parseFloat(entropy);

    // Update Progress Bar
    const fillPercent = Math.min(100, Math.max(5, (entropyNum / 100) * 100));
    progressBar.style.width = `${fillPercent}%`;

    let colorClass = 'bg-slate-700';
    let strengthText = 'Weak';
    let strengthBadgeClass = 'bg-rose-500/10 text-rose-400 border-rose-500/20';

    if (entropyNum < 35) {
      colorClass = 'bg-rose-500';
      strengthText = 'Weak';
      strengthBadgeClass = 'bg-rose-500/10 text-rose-400 border-rose-500/20';
    } else if (entropyNum < 60) {
      colorClass = 'bg-amber-500';
      strengthText = 'Moderate';
      strengthBadgeClass = 'bg-amber-500/10 text-amber-400 border-amber-500/20';
    } else if (entropyNum < 90) {
      colorClass = 'bg-emerald-500';
      strengthText = 'Strong';
      strengthBadgeClass = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
    } else {
      colorClass = 'bg-emerald-400';
      strengthText = 'Enterprise';
      strengthBadgeClass = 'bg-emerald-400/20 text-emerald-300 border-emerald-400/30';
    }

    progressBar.className = `h-full ${colorClass} progress-bar-fill rounded-full`;
    entropyReadout.textContent = `${entropyNum} bits entropy`;
    strengthLabel.textContent = `${strengthText} (${length} chars)`;

    entropyValue.textContent = entropyNum;
    strengthBadge.textContent = strengthText;
    strengthBadge.className = `px-2.5 py-0.5 rounded-full text-xs font-medium border ${strengthBadgeClass}`;

    poolSizeValue.textContent = poolSize;
    poolSizeBadge.textContent = `${poolSize} Pool Size`;

    // Toggle Pool Tags
    toggleTag(tagLower, hasLower, 'a-z (26)');
    toggleTag(tagUpper, hasUpper, 'A-Z (26)');
    toggleTag(tagDigits, hasDigits, '0-9 (10)');
    toggleTag(tagSymbols, hasSymbols, '!@#$ (32)');
  }

  function toggleTag(element, active, label) {
    if (active) {
      element.className = 'px-2 py-0.5 rounded border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 font-medium';
    } else {
      element.className = 'px-2 py-0.5 rounded border border-slate-800 bg-slate-950 text-slate-600';
    }
  }

  // --- Fetch Backend Full Audit ---
  async function fetchBackendAudit(password) {
    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password })
      });

      if (!response.ok) {
        throw new Error(`HTTP Error ${response.status}`);
      }

      const data = await response.json();
      updateBackendResults(data);
      liveStatusText.textContent = 'Audit complete';
    } catch (err) {
      console.error('Audit Error:', err);
      liveStatusText.textContent = 'Offline evaluation';
    }
  }

  function updateBackendResults(data) {
    // 1. Crack time display
    crackTimeValue.textContent = data.crack_time_display || 'Instant';

    // 2. Breach badge update
    if (data.is_breached) {
      const formattedCount = data.breach_count ? data.breach_count.toLocaleString() : '1+';
      breachBadgeContainer.innerHTML = `
        <span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30">
          <span class="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></span>
          Exposed in ${formattedCount} data breaches
        </span>
      `;
    } else {
      breachBadgeContainer.innerHTML = `
        <span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
          <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
          No known breaches found
        </span>
      `;
    }

    // SHA-1 verification detail text
    if (data.sha1_prefix) {
      sha1PrefixText.textContent = `${data.sha1_prefix} | Masked Suffix: ${data.sha1_suffix_masked || '••••••••'}`;
    }

    // 3. Recommendations list
    renderRecommendations(data.recommendations || []);
  }

  function renderRecommendations(list) {
    if (!list || list.length === 0) {
      recommendationList.innerHTML = `
        <li class="flex items-start gap-2.5 text-slate-400">
          <span class="mt-0.5 text-slate-600">•</span>
          <span>No security issues identified.</span>
        </li>
      `;
      return;
    }

    recommendationList.innerHTML = list.map(rec => {
      const isPositive = rec.includes('Excellent') || rec.includes('Meets top');
      const icon = isPositive ? `
        <span class="mt-0.5 p-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
          <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
          </svg>
        </span>
      ` : `
        <span class="mt-0.5 p-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20">
          <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
        </span>
      `;
      return `
        <li class="flex items-start gap-2.5">
          ${icon}
          <span class="text-slate-300">${rec}</span>
        </li>
      `;
    }).join('');
  }

  function resetDashboard() {
    progressBar.style.width = '0%';
    progressBar.className = 'h-full bg-slate-700 progress-bar-fill rounded-full';
    entropyReadout.textContent = '0.0 bits entropy';
    strengthLabel.textContent = 'Enter password';
    liveStatusText.textContent = 'Ready to audit';

    entropyValue.textContent = '0.0';
    strengthBadge.textContent = 'Pending';
    strengthBadge.className = 'px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-800 text-slate-400 border border-slate-700';

    poolSizeValue.textContent = '0';
    poolSizeBadge.textContent = '0 Pool Size';

    toggleTag(tagLower, false, 'a-z (26)');
    toggleTag(tagUpper, false, 'A-Z (26)');
    toggleTag(tagDigits, false, '0-9 (10)');
    toggleTag(tagSymbols, false, '!@#$ (32)');

    breachBadgeContainer.innerHTML = `
      <span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-slate-800 text-slate-400 border border-slate-700">
        <span class="w-1.5 h-1.5 rounded-full bg-slate-500"></span>
        Awaiting Audit
      </span>
    `;
    sha1PrefixText.textContent = '-----';
    crackTimeValue.textContent = 'Instant';

    renderRecommendations(['Enter a password above to receive real-time security guidance.']);
  }
});
