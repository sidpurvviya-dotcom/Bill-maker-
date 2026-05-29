/**
 * Bill Maker — JavaScript Engine
 * Includes: Firebase Auth guard, Firestore bill records, live bill editing
 */

// ── Local Auth Setup ──
let CURRENT_USER = null;  // currently signed-in user session

(function initAuth() {
  const activeSession = localStorage.getItem('bm_current_session');
  if (!activeSession) {
    // Redirect to login page immediately
    window.location.href = 'login.html';
    return;
  }
  
  try {
    CURRENT_USER = JSON.parse(activeSession);
    if (!CURRENT_USER || CURRENT_USER.role !== 'user') {
      throw new Error('Invalid user session');
    }
  } catch (err) {
    console.warn('Auth session validation error:', err);
    localStorage.removeItem('bm_current_session');
    window.location.href = 'login.html';
    return;
  }

  // Check subscription suspended state
  try {
    const usersData = localStorage.getItem('bm_local_users');
    if (usersData) {
      const users = JSON.parse(usersData);
      if (Array.isArray(users)) {
        const u = users.find(usr => (usr.email || usr.userId || '').toLowerCase() === CURRENT_USER.email.toLowerCase());
        if (u && u.subscriptionState && u.subscriptionState !== 'active') {
          alert('❌ आपका खाता निलंबित (Suspended) या समाप्त हो चुका है। कृपया एडमिन से संपर्क करें।');
          localStorage.removeItem('bm_current_session');
          window.location.href = 'login.html';
          return;
        }
      }
    }
  } catch (err) {
    console.warn('Subscription guard validation error:', err);
  }
  
  // Hide overlay
  const overlay = document.getElementById('authOverlay');
  if (overlay) overlay.style.display = 'none';

  // Wait for DOM to finish loading to show user info
  window.addEventListener('DOMContentLoaded', () => {
    showUserInfo(CURRENT_USER);
  });
})();

// ── Show logged-in user info in header ──
function showUserInfo(user) {
  const infoEl   = document.getElementById('userInfo');
  const avatarEl = document.getElementById('userAvatar');
  const avatarPlaceholder = document.getElementById('userAvatarPlaceholder');
  const nameEl   = document.getElementById('userName');
  const emailEl  = document.getElementById('userEmail');
  const logoutEl = document.getElementById('btnLogout');

  if (infoEl)   infoEl.style.display   = 'flex';
  if (logoutEl) logoutEl.style.display = 'inline-flex';
  
  const initials = (user.shopName || 'U').charAt(0).toUpperCase();
  
  if (user.picture) {
    if (avatarEl) {
      avatarEl.src = user.picture;
      avatarEl.style.display = 'block';
    }
    if (avatarPlaceholder) avatarPlaceholder.style.display = 'none';
  } else {
    if (avatarPlaceholder) {
      avatarPlaceholder.textContent = initials;
      avatarPlaceholder.style.display = 'flex';
    }
    if (avatarEl) avatarEl.style.display = 'none';
  }
  
  if (nameEl)   nameEl.textContent  = user.shopName || 'यूज़र';
  if (emailEl)  emailEl.textContent = user.email || '';

  // Wire logout button
  if (logoutEl) {
    logoutEl.addEventListener('click', () => {
      if (confirm('लोगआउट करना चाहते हैं?')) {
        localStorage.removeItem('bm_current_session');
        window.location.href = 'login.html';
      }
    });
  }
}

// ── Save current bill to localStorage ──
async function saveBillRecord(invoiceNo) {
  if (!CURRENT_USER) return;
  if (!S.bill.receiverName) return; // Don't save if no receiver name

  try {
    const billData = {
      id:              S.bill.id || 'off_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9),
      invoiceNo:       invoiceNo,
      date:            S.bill.date,
      receiverName:    S.bill.receiverName.trim(),
      receiverAddress: S.bill.receiverAddress,
      vehicleInfo:     S.bill.vehicleInfo,
      billType:        S.bill.billType,
      items:           S.items.map(item => ({
        name:     item.name,
        qty:      item.qty,
        uom:      item.uom,
        rate:     item.rate,
        discount: item.discount,
        amount:   item._amount || 0
      })),
      charges:  { ...S.charges },
      totals:   S._totals ? {
        subtotal: S._totals.subtotal,
        net:      S._totals.net
      } : { subtotal: 0, net: 0 },
      businessName: S.profile.businessName,
      createdAt: new Date().toISOString()
    };

    const storageKey = 'bm_bills_' + CURRENT_USER.email;
    const existingData = localStorage.getItem(storageKey);
    let bills = existingData ? JSON.parse(existingData) : [];

    // Find and update or append
    const idx = bills.findIndex(b => b.id === billData.id);
    if (idx !== -1) {
      billData.paid = (bills[idx].paid !== undefined) ? bills[idx].paid : false;
      bills[idx] = billData;
    } else {
      billData.paid = false;
      bills.unshift(billData);
    }

    localStorage.setItem(storageKey, JSON.stringify(bills));
    console.log('✅ Bill saved to local storage:', invoiceNo);

    // Sync metrics to central user registry for Admin dashboard
    try {
      const usersData = localStorage.getItem('bm_local_users');
      if (usersData) {
        let users = JSON.parse(usersData);
        let uIdx = users.findIndex(u => (u.email || u.userId || '').toLowerCase() === CURRENT_USER.email.toLowerCase());
        if (uIdx !== -1) {
          if (!users[uIdx].stats) {
            users[uIdx].stats = { lastLogin: null, lastActive: null, sessionCount: 0, totalBills: 0 };
          }
          users[uIdx].stats.lastActive = new Date().toISOString();
          users[uIdx].stats.totalBills = bills.length;
          localStorage.setItem('bm_local_users', JSON.stringify(users));
        }
      }
    } catch(syncErr) {
      console.warn('Central stats sync warning:', syncErr);
    }
    
    // Refresh history panel silently in the editor tab if open
    loadBillHistory();
  } catch(err) {
    console.error('Local storage save error:', err);
  }
}

// Toggle paid/unpaid status in local storage
function toggleBillPaidStatus(billId, currentStatus) {
  if (!CURRENT_USER) return;
  try {
    const storageKey = 'bm_bills_' + CURRENT_USER.email;
    const existingData = localStorage.getItem(storageKey);
    let bills = existingData ? JSON.parse(existingData) : [];
    
    const idx = bills.findIndex(b => b.id === billId);
    if (idx !== -1) {
      bills[idx].paid = !currentStatus;
      localStorage.setItem(storageKey, JSON.stringify(bills));
      console.log('✅ Bill paid status updated:', bills[idx].paid);
      
      // Reload history list with current search query
      const q = el('historySearch')?.value || '';
      loadBillHistory(q);
      showToast(bills[idx].paid ? '✅ Bill marked as PAID' : '⏳ Bill marked as UNPAID');
    }
  } catch (err) {
    console.error('Error updating paid status:', err);
  }
}

// Delete bill record from local storage
function deleteBillRecord(billId, invoiceNo) {
  if (!CURRENT_USER) return;
  if (!confirm(`क्या आप सच में बिल नं ${invoiceNo} को हटाना चाहते हैं?`)) return;

  try {
    const storageKey = 'bm_bills_' + CURRENT_USER.email;
    const existingData = localStorage.getItem(storageKey);
    let bills = existingData ? JSON.parse(existingData) : [];
    
    const filtered = bills.filter(b => b.id !== billId);
    localStorage.setItem(storageKey, JSON.stringify(filtered));
    console.log('🗑️ Bill deleted:', invoiceNo);
    
    // Sync central user stats if available
    try {
      const usersData = localStorage.getItem('bm_local_users');
      if (usersData) {
        let users = JSON.parse(usersData);
        let uIdx = users.findIndex(u => (u.email || u.userId || '').toLowerCase() === CURRENT_USER.email.toLowerCase());
        if (uIdx !== -1) {
          if (!users[uIdx].stats) {
            users[uIdx].stats = { lastLogin: null, lastActive: null, sessionCount: 0, totalBills: 0 };
          }
          users[uIdx].stats.totalBills = filtered.length;
          localStorage.setItem('bm_local_users', JSON.stringify(users));
        }
      }
    } catch (syncErr) {
      console.warn('Central stats sync warning on delete:', syncErr);
    }
    
    // Reload history list with current search query
    const q = el('historySearch')?.value || '';
    loadBillHistory(q);
    showToast('🗑️ बिल सफलतापूर्वक हटा दिया गया है।');
  } catch (err) {
    console.error('Error deleting bill:', err);
    showToast('❌ बिल हटाने में त्रुटि आई।');
  }
}

// ── Load bill history from localStorage ──
async function loadBillHistory(searchQuery = '') {
  if (!CURRENT_USER) return;

  const listEl  = document.getElementById('historyList');
  const emptyEl = document.getElementById('historyEmpty');
  if (!listEl) return;

  try {
    const storageKey = 'bm_bills_' + CURRENT_USER.email;
    const existingData = localStorage.getItem(storageKey);
    let bills = existingData ? JSON.parse(existingData) : [];

    // Filter by search query (shop name)
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      bills = bills.filter(b =>
        (b.receiverName || '').toLowerCase().includes(q) ||
        (b.invoiceNo || '').toLowerCase().includes(q)
      );
    }

    // Clear current list
    listEl.innerHTML = '';

    if (bills.length === 0) {
      if (emptyEl) {
        listEl.appendChild(emptyEl);
      } else {
        const customEmpty = document.createElement('div');
        customEmpty.style.textAlign = 'center';
        customEmpty.style.padding = '40px 20px';
        customEmpty.style.color = '#9ca3af';
        customEmpty.innerHTML = `
          <div style="font-size:40px;margin-bottom:12px">📂</div>
          <div style="font-weight:600;margin-bottom:6px">अभी कोई बिल सेव नहीं हुआ</div>
          <div style="font-size:12px">Print करने पर बिल ऑटोमैटिक सेव होगा</div>
        `;
        listEl.appendChild(customEmpty);
      }
      return;
    }

    // Group bills by receiver shop name
    const groups = {};
    bills.forEach(bill => {
      const key = (bill.receiverName || 'अज्ञात दुकान').trim();
      if (!groups[key]) groups[key] = [];
      groups[key].push(bill);
    });

    // Render grouped cards
    Object.entries(groups).forEach(([shopName, shopBills]) => {
      // Group header
      const header = document.createElement('div');
      header.className = 'history-group-header';
      header.textContent = `🏢 ${shopName} (${shopBills.length} बिल)`;
      listEl.appendChild(header);

      // Bill cards for this shop
      shopBills.forEach(bill => {
        const card = document.createElement('div');
        card.className = 'history-bill-card';

        const dateStr = bill.date
          ? bill.date.split('-').reverse().join('/')
          : '—';

        const netAmt = bill.totals?.net || 0;
        const isPaid = !!bill.paid;

        card.innerHTML = `
          <div class="hbc-icon">${bill.billType === 'challan' ? '🚚' : '🧾'}</div>
          <div class="hbc-info">
            <div class="hbc-shop">${safeEsc(bill.receiverName) || '—'}</div>
            <div class="hbc-meta">बिल नं: <strong>${safeEsc(bill.invoiceNo)}</strong> &nbsp;&bull;&nbsp; ${bill.items?.length || 0} items</div>
          </div>
          <div class="hbc-amount">
            <div class="hbc-amt-val">₹ ${Number(netAmt).toLocaleString('en-IN')}</div>
            <div class="hbc-date">${dateStr}</div>
          </div>
          <div class="hbc-actions">
            <button class="btn-status ${isPaid ? 'paid' : 'unpaid'}" title="स्थिति बदलें">
              ${isPaid ? 'Paid' : 'Unpaid'}
            </button>
            <button class="btn-delete-bill" title="बिल हटाएं">🗑️</button>
          </div>
        `;

        // Wire click events and stop propagation
        const btnStatus = card.querySelector('.btn-status');
        if (btnStatus) {
          btnStatus.addEventListener('click', (e) => {
            e.stopPropagation();
            toggleBillPaidStatus(bill.id, isPaid);
          });
        }

        const btnDelete = card.querySelector('.btn-delete-bill');
        if (btnDelete) {
          btnDelete.addEventListener('click', (e) => {
            e.stopPropagation();
            deleteBillRecord(bill.id, bill.invoiceNo);
          });
        }

        // Click to reload this bill into the editor
        card.addEventListener('click', () => loadBillFromRecord(bill));
        listEl.appendChild(card);
      });
    });

  } catch(err) {
    console.error('Local storage history load error:', err);
    listEl.innerHTML = '<div style="padding:20px;text-align:center;color:#ef4444">❌ History load नहीं हुआ। check browser data.</div>';
  }
}

// ── Apply a saved bill record into the editor state ──
function applyBillRecord(bill) {
  S.bill.id              = bill.id || null;
  S.bill.invoiceNo       = bill.invoiceNo || '';
  S.bill.date            = bill.date || getToday();
  S.bill.receiverName    = bill.receiverName || '';
  S.bill.receiverAddress = bill.receiverAddress || '';
  S.bill.vehicleInfo     = bill.vehicleInfo || '';
  S.bill.billType        = bill.billType || 'estimate';

  S.items = (bill.items || []).map((item, i) => ({
    id: i + 1,
    name:     item.name || '',
    qty:      parseFloat(item.qty) || 0,
    uom:      item.uom || '',
    rate:     parseFloat(item.rate) || 0,
    discount: String(item.discount || '0')
  }));

  if (bill.charges) {
    S.charges = { ...S.charges, ...bill.charges };
  }
}

// ── Load a saved bill record back into editor (called from History tab inside editor) ──
function loadBillFromRecord(bill) {
  if (!confirm(`"${bill.receiverName}" का बिल नं ${bill.invoiceNo} editor में लोड करें?`)) return;

  applyBillRecord(bill);

  // Refresh UI
  fillFormFromState();
  renderItemsTable();
  recalcAndUpdate();
  applyBillType(S.bill.billType);

  // Switch to Bill Info tab
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.querySelector('[data-tab="tab-bill"]')?.classList.add('active');
  document.getElementById('tab-bill')?.classList.add('active');

  showToast('✅ बिल लोड हो गया! अब आप edit कर सकते हैं।');
}

function safeEsc(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Application State ──
const S = {
  profile: {
    religiousHeader: '|| श्री गणेशाय नमः ||',
    businessName: 'S.V.K.B. किराना स्टोर',
    subtitle: 'Wholesale Kirana Merchants & Commission Agent',
    phone: '9876543210',
    gstin: '',
    address: 'गल्ला मंडी, गोरखपुर, UP',
    terms: 'पेमेंट कंडीशन 20 दिन, इसके ऊपर 2% ब्याज लगेगा।\nबिका हुआ माल वापस नहीं होगा।'
  },
  bill: {
    invoiceNo: '101',
    date: getToday(),
    vehicleInfo: '',
    receiverName: '',
    receiverAddress: '',
    billType: 'estimate',
    pageSize: 'A4',
    autoIncrement: true
  },
  items: [],
  charges: { hammali: 0, hammaliNag: 0, hammaliRate: 0, bori: 0, gstRate: 0, advance: 0 }
};


// ── Utility helpers ──
function getToday() {
  return new Date().toISOString().split('T')[0];
}

function fmtDate(iso) {
  if (!iso) return '';
  const [y, m, d] = iso.split('-');
  return `${d}/${m}/${y}`;
}

function fmtRs(n) {
  const num = parseFloat(n) || 0;
  return '₹ ' + num.toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function calcItemDiscount(rawTotal, discount) {
  if (!discount || String(discount).trim() === '0' || String(discount).trim() === '') return 0;
  const ds = String(discount).trim();
  if (ds.endsWith('%')) {
    const pct = parseFloat(ds) || 0;
    return rawTotal * (pct / 100);
  }
  return parseFloat(ds) || 0;
}


function el(id) { return document.getElementById(id); }
function setText(id, val) { const e = el(id); if (e) e.textContent = String(val || ''); }
function showHide(id, show) { const e = el(id); if (e) e.style.display = show ? '' : 'none'; }

// ── Startup ──
document.addEventListener('DOMContentLoaded', () => {
  loadStorage();

  // If coming from dashboard with a bill to load, restore it first
  const pendingBill = sessionStorage.getItem('bm_load_bill');
  if (pendingBill) {
    try {
      const bill = JSON.parse(pendingBill);
      sessionStorage.removeItem('bm_load_bill');
      applyBillRecord(bill);
    } catch(e) { console.warn('Session bill load error', e); }
  }

  fillFormFromState();
  renderItemsTable();
  recalcAndUpdate();
  wireAllEvents();
  applyBillType(S.bill.billType);
  updatePaperSize(S.bill.pageSize);
});

// ── Toast notification ──
function showToast(msg, duration = 3000) {
  const t = document.getElementById('editorToast');
  if (!t) return;
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), duration);
}

// ── LocalStorage ──
function loadStorage() {
  try {
    const p = localStorage.getItem('bm_profile');
    if (p) S.profile = { ...S.profile, ...JSON.parse(p) };
    const b = localStorage.getItem('bm_bill_config');
    if (b) {
      const parsed = JSON.parse(b);
      S.bill = { ...S.bill, ...parsed };
    }

    // Sync billing preferences from global user registry if set
    if (CURRENT_USER) {
      const usersData = localStorage.getItem('bm_local_users');
      if (usersData) {
        const users = JSON.parse(usersData);
        const u = users.find(usr => (usr.email || usr.userId || '').toLowerCase() === CURRENT_USER.email.toLowerCase());
        if (u && u.billingPreferences) {
          // Map A4/2 user settings to A5-Portrait internal printer configurations
          S.bill.pageSize = u.billingPreferences.pageSize === 'A4/2' ? 'A5-Portrait' : 'A4';
          S.bill.autoIncrement = u.billingPreferences.autoIncrement !== undefined ? u.billingPreferences.autoIncrement : S.bill.autoIncrement;

          // Sync persistent business profile attributes
          S.profile.businessName = u.shopName || S.profile.businessName;
          S.profile.religiousHeader = u.billingPreferences.religiousHeader || S.profile.religiousHeader;
          S.profile.phone = u.billingPreferences.phone || S.profile.phone;
          S.profile.gstin = u.billingPreferences.gstin || S.profile.gstin;
          S.profile.address = u.billingPreferences.address || S.profile.address;
          S.profile.terms = u.billingPreferences.terms || S.profile.terms;
        }
      }
    }
  } catch (e) { console.warn('Storage load error', e); }
}

function saveStorage() {
  try {
    localStorage.setItem('bm_profile', JSON.stringify(S.profile));
    // Only save config (not session bill data)
    localStorage.setItem('bm_bill_config', JSON.stringify({
      invoiceNo: S.bill.invoiceNo,
      billType: S.bill.billType,
      pageSize: S.bill.pageSize,
      autoIncrement: S.bill.autoIncrement
    }));

    // Update global user registry configurations and activity stats
    if (CURRENT_USER) {
      const usersData = localStorage.getItem('bm_local_users');
      if (usersData) {
        let users = JSON.parse(usersData);
        let uIdx = users.findIndex(u => (u.email || u.userId || '').toLowerCase() === CURRENT_USER.email.toLowerCase());
        if (uIdx !== -1) {
          users[uIdx].billingPreferences = {
            pageSize: S.bill.pageSize,
            autoIncrement: S.bill.autoIncrement
          };
          if (!users[uIdx].stats) {
            users[uIdx].stats = { lastLogin: null, lastActive: null, sessionCount: 0, totalBills: 0 };
          }
          users[uIdx].stats.lastActive = new Date().toISOString();
          localStorage.setItem('bm_local_users', JSON.stringify(users));
        }
      }
    }
  } catch (e) { console.warn('Storage save error', e); }
}

// ── Populate form from state ──
function fillFormFromState() {
  const setVal = (id, val) => { const e = el(id); if (e) e.value = (val !== undefined && val !== null) ? val : ''; };

  setVal('profBusinessName',   S.profile.businessName);
  setVal('profPhone',          S.profile.phone);
  setVal('profGSTIN',          S.profile.gstin);
  setVal('profAddress',        S.profile.address);
  setVal('profReligiousHeader',S.profile.religiousHeader);
  setVal('profTerms',          S.profile.terms);

  setVal('metaInvoiceNo',      S.bill.invoiceNo);
  setVal('metaDate',           S.bill.date || getToday());
  setVal('metaVehicleInfo',    S.bill.vehicleInfo);
  setVal('metaReceiverName',   S.bill.receiverName);
  setVal('metaReceiverAddress',S.bill.receiverAddress);
  setVal('layoutPageSize',     S.bill.pageSize);

  setVal('calcHammaliNag',  S.charges.hammaliNag || 0);
  setVal('calcHammaliRate', S.charges.hammaliRate || 0);
  // Legacy hidden field
  setVal('calcHammali', S.charges.hammali);
  setVal('calcBori',     S.charges.bori);
  setVal('calcTaxGST',   S.charges.gstRate);
  setVal('calcAdvance',  S.charges.advance);
  setVal('settingNextNo',S.bill.invoiceNo);

  // Radio buttons
  const btEl = document.querySelector(`input[name="billType"][value="${S.bill.billType}"]`);
  if (btEl) btEl.checked = true;

  const aiVal = S.bill.autoIncrement ? 'yes' : 'no';
  const aiEl = document.querySelector(`input[name="autoIncr"][value="${aiVal}"]`);
  if (aiEl) aiEl.checked = true;
}

// ── Item CRUD ──
function getNextId() {
  return S.items.length > 0 ? Math.max(...S.items.map(i => i.id)) + 1 : 1;
}

function addItem(name = '', qty = 1, uom = '', rate = 0, discount = '0') {
  S.items.push({
    id:       getNextId(),
    name:     String(name),
    qty:      parseFloat(qty) || 0,
    uom:      String(uom).toUpperCase(),
    rate:     parseFloat(rate) || 0,
    discount: String(discount)
  });
  renderItemsTable();
  recalcAndUpdate();
  checkOverflow();

  // Auto-focus last row's name field
  setTimeout(() => {
    const rows = document.querySelectorAll('#itemsBody tr');
    if (rows.length > 0) {
      const lastRow = rows[rows.length - 1];
      const nameInp = lastRow.querySelector('.inp-name');
      if (nameInp) nameInp.focus();
    }
  }, 50);
}

function deleteItem(id) {
  S.items = S.items.filter(i => i.id !== id);
  renderItemsTable();
  recalcAndUpdate();
  checkOverflow();
}

// ── Render the editable items table (sidebar) ──
function renderItemsTable() {
  const tbody = el('itemsBody');
  if (!tbody) return;
  tbody.innerHTML = '';

  S.items.forEach((item, idx) => {
    // Pre-calculate amount for display
    const raw  = item.qty * item.rate;
    const disc = calcItemDiscount(raw, item.discount);
    const amt  = Math.max(0, raw - disc);

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="text-align:center;color:#aaa;font-size:11px;width:22px">${idx + 1}</td>
      <td><input class="inp-name"  type="text"   value="${safeEsc(item.name)}"     placeholder="सामान का नाम" data-field="name"></td>
      <td><input class="inp-qty"   type="number" value="${item.qty}"               min="0" step="any" data-field="qty"  style="width:60px"></td>
      <td><input class="inp-uom"   type="text"   value="${safeEsc(item.uom)}"      placeholder="KG/BOX" data-field="uom" style="width:65px"></td>
      <td><input class="inp-rate"  type="number" value="${item.rate}"              min="0" step="any" data-field="rate" style="width:80px"></td>
      <td><input class="inp-disc"  type="text"   value="${safeEsc(item.discount)}" placeholder="0 या 5%" data-field="discount" style="width:65px" title="जैसे 20 (सिर्फ) या 5% (पर्सेंट)"></td>
      <td class="row-amount">${fmtRs(amt)}</td>
      <td><button class="btn-del-row" title="हटाएं">✕</button></td>
    `;

    // Wire each input change
    tr.querySelectorAll('input').forEach(inp => {
      const fieldName = inp.dataset.field;  // captured in outer scope

      inp.addEventListener('input', () => {
        const v = inp.value;
        if      (fieldName === 'name')     item.name     = v;
        else if (fieldName === 'qty')      item.qty      = parseFloat(v) || 0;
        else if (fieldName === 'uom')      item.uom      = v.toUpperCase();
        else if (fieldName === 'rate')     item.rate     = parseFloat(v) || 0;
        else if (fieldName === 'discount') item.discount = v;

        // Update this row's amount cell immediately
        const r2  = item.qty * item.rate;
        const d2  = calcItemDiscount(r2, item.discount);
        const amtCell = tr.querySelector('.row-amount');
        if (amtCell) amtCell.textContent = fmtRs(Math.max(0, r2 - d2));

        recalcAndUpdate();
      });

      // Tab on 'discount' of last row → add new empty row
      if (fieldName === 'discount') {
        inp.addEventListener('keydown', e => {
          if (e.key === 'Tab' && !e.shiftKey && idx === S.items.length - 1) {
            e.preventDefault();
            addItem();
          }
        });
      }
    });

    tr.querySelector('.btn-del-row').addEventListener('click', () => deleteItem(item.id));
    tbody.appendChild(tr);
  });
}

// ── Recalculate all totals and update preview ──
function recalcAndUpdate() {
  // 1. Calculate each item's amount
  let subtotal = 0;
  S.items.forEach(item => {
    const raw  = item.qty * item.rate;
    const disc = calcItemDiscount(raw, item.discount);
    item._amount = Math.max(0, raw - disc);
    subtotal += item._amount;
  });

  // 2. Extra charges
  const hmNag  = parseFloat(S.charges.hammaliNag)  || 0;
  const hmRate = parseFloat(S.charges.hammaliRate) || 0;
  const hm     = Math.round(hmNag * hmRate * 100) / 100;  // Hammali = nag × rate
  S.charges.hammali = hm; // keep legacy field synced

  const bo = parseFloat(S.charges.bori)    || 0;
  const gt = parseFloat(S.charges.gstRate) || 0;
  const av = parseFloat(S.charges.advance) || 0;
  const gstAmt = subtotal * gt / 100;

  // Hammali IS now included in net total
  const net = Math.round(subtotal + hm + bo + gstAmt - av);

  // Update formula display
  const formulaEl = document.getElementById('hammaliFormula');
  const formulaTxt = document.getElementById('hammaliFormulaText');
  if (formulaEl && formulaTxt) {
    if (hmNag > 0 || hmRate > 0) {
      formulaTxt.textContent = hmNag + ' नग × ₹' + hmRate + ' = ₹' + hm.toFixed(2);
      formulaEl.style.display = 'block';
    } else {
      formulaEl.style.display = 'none';
    }
  }

  // Store computed totals
  S._totals = { subtotal, hm, hmNag, hmRate, bo, gt, av, gstAmt, net };

  // 3. Update sidebar summary section (tab 3)
  setText('liveSubtotal', fmtRs(subtotal));
  setText('sumSubtotal',  fmtRs(subtotal));
  setText('sumHammali',   fmtRs(hm));
  setText('sumHammaliNag', hmNag);
  setText('sumHammaliRateDisplay', hmRate);
  setText('sumBori',      fmtRs(bo));
  setText('sumGstPct',    gt);
  setText('sumGst',       fmtRs(gstAmt));
  setText('sumAdvance',   fmtRs(av));
  setText('sumNet',       fmtRs(net));

  showHide('sumHammaliRow', hm > 0);
  showHide('sumBoriRow',    bo > 0);
  showHide('sumGstRow',     gt > 0);
  showHide('sumAdvanceRow', av > 0);

  // 4. Update the live print preview
  updateBillPreview();
}

// ── Update the live bill print preview ──
function updateBillPreview() {
  if (!S._totals) return;
  const t = S._totals;

  // Business profile
  setText('pReligious',  S.profile.religiousHeader);
  setText('pBizName',    S.profile.businessName);
  setText('pBizSub',     S.profile.subtitle);
  setText('pBizAddr',    S.profile.address);
  setText('pTerms',      S.profile.terms);
  setText('pBizSignName',S.profile.businessName);

  showHide('pPhoneBlock', !!S.profile.phone);
  setText('pPhone', S.profile.phone);
  showHide('pGstBlock', !!S.profile.gstin);
  setText('pGST', S.profile.gstin);

  // Bill metadata
  setText('pRecvName',   S.bill.receiverName   || '—');
  setText('pRecvAddr',   S.bill.receiverAddress || '');
  setText('pInvoiceNo',  S.bill.invoiceNo);
  setText('pDate',       fmtDate(S.bill.date));

  showHide('pVehicleRow', !!S.bill.vehicleInfo);
  setText('pVehicle', S.bill.vehicleInfo);

  // Items rows in bill preview
  const previewBody = el('pItemsBody');
  if (previewBody) {
    previewBody.innerHTML = '';
    const isChallan = S.bill.billType === 'challan';

    S.items.forEach((item, i) => {
      const tr = document.createElement('tr');
      // Qty + Unit combined e.g. "25 BORI"
      const qtyDisplay = `${item.qty}${item.uom ? ' ' + item.uom : ''}`;
      let html = `
        <td class="tc">${i + 1}</td>
        <td style="font-weight:600">${safeEsc(item.name) || '—'}</td>
        <td class="tr">${qtyDisplay}</td>
      `;
      if (!isChallan) {
        html += `
          <td class="tr">₹${Number(item.rate).toFixed(2)}</td>
          <td class="tr">${item.discount && item.discount !== '0' ? item.discount : '—'}</td>
          <td class="tr" style="font-weight:700">₹${Number(item._amount || 0).toFixed(2)}</td>
        `;
      }
      tr.innerHTML = html;
      previewBody.appendChild(tr);
    });
  }

  // Totals block in bill preview (hidden for challan)
  const isChallan = S.bill.billType === 'challan';
  showHide('pTotalsBlock', !isChallan);

  if (!isChallan) {
    setText('pSubtotal', fmtRs(t.subtotal));
    setText('pBori',     fmtRs(t.bo));
    setText('pGstPct',   t.gt);
    setText('pGst',      fmtRs(t.gstAmt));
    setText('pAdvance',  fmtRs(t.av));
    setText('pNetTotal', fmtRs(t.net));

    showHide('pBoriRow',    t.bo > 0);
    showHide('pGstRow',     t.gt > 0);
    showHide('pAdvanceRow', t.av > 0);

    // Hammali: now INCLUDED in net total, shown as a line item with breakdown
    showHide('pHammaliRow', t.hm > 0);
    if (t.hm > 0) {
      setText('pHammali',     fmtRs(t.hm));
      setText('pHammaliNag',  t.hmNag || 0);
      setText('pHammaliRate', t.hmRate || 0);
    }
  }
}

// ── Switch bill type (Estimate vs Challan) ──
function applyBillType(type) {
  S.bill.billType = type;
  const isChallan = type === 'challan';

  // Update bill title
  const docType = el('pDocType');
  if (docType) docType.textContent = isChallan
    ? '— DELIVERY CHALLAN / डिलिवरी चालान —'
    : '— ESTIMATE / अनुमानित बिल —';

  // Update label
  const billNoLbl = el('pBillNoLabel');
  if (billNoLbl) billNoLbl.textContent = isChallan ? 'चालान नं:' : 'बिल नं:';

  // Show/hide financial columns in preview table
  ['thRate', 'thDisc', 'thAmt'].forEach(id => {
    showHide(id, !isChallan);
  });

  showHide('pTotalsBlock', !isChallan);
  recalcAndUpdate();
}

// ── Update paper size ──
function updatePaperSize(size) {
  const paper = el('invoicePaper');
  if (!paper) return;

  paper.className = 'bill-paper'; // reset
  const classMap = {
    'A4':          'size-a4',
    'A5-Portrait': 'size-a5-p',
    'A5-Landscape':'size-a5-l'
  };
  paper.classList.add(classMap[size] || 'size-a4');

  const labelMap = {
    'A4':          'A4 (पूरा पेज - 210×297mm)',
    'A5-Portrait': 'A5 Portrait (आधा पेज)',
    'A5-Landscape':'A5 Landscape (आड़ा)'
  };
  setText('previewSizeLabel', labelMap[size] || size);
}

// ── Overflow warning ──
function checkOverflow() {
  const alertEl = el('overflowAlert');
  if (!alertEl) return;
  const limits = { 'A4': 20, 'A5-Portrait': 10, 'A5-Landscape': 6 };
  const limit = limits[S.bill.pageSize] || 20;
  alertEl.style.display = S.items.length > limit ? 'block' : 'none';
}

// ── Bind a form field to state ──
function onInput(id, fn) {
  const e = el(id);
  if (!e) return;
  const handler = () => fn(e.value);
  e.addEventListener('input',  handler);
  e.addEventListener('change', handler); // for <select>
}

// ── Wire all form events ──
function wireAllEvents() {

  // ── TAB BUTTONS ──
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      const target = el(btn.dataset.tab);
      if (target) target.classList.add('active');
    });
  });

  // ── PROFILE FIELDS ──
  onInput('profBusinessName',    v => { S.profile.businessName    = v; saveStorage(); updateBillPreview(); });
  onInput('profPhone',           v => { S.profile.phone           = v; saveStorage(); updateBillPreview(); });
  onInput('profGSTIN',           v => { S.profile.gstin           = v; saveStorage(); updateBillPreview(); });
  onInput('profAddress',         v => { S.profile.address         = v; saveStorage(); updateBillPreview(); });
  onInput('profReligiousHeader', v => { S.profile.religiousHeader = v; saveStorage(); updateBillPreview(); });
  onInput('profTerms',           v => { S.profile.terms           = v; saveStorage(); updateBillPreview(); });

  // ── BILL META FIELDS ──
  onInput('metaInvoiceNo',       v => { S.bill.invoiceNo      = v;            saveStorage(); updateBillPreview(); });
  onInput('metaDate',            v => { S.bill.date           = v;            updateBillPreview(); });
  onInput('metaVehicleInfo',     v => { S.bill.vehicleInfo    = v;            updateBillPreview(); });
  onInput('metaReceiverName',    v => { S.bill.receiverName   = v;            updateBillPreview(); });
  onInput('metaReceiverAddress', v => { S.bill.receiverAddress= v;            updateBillPreview(); });

  // ── BILL TYPE RADIOS ──
  document.querySelectorAll('input[name="billType"]').forEach(r => {
    r.addEventListener('change', e => {
      applyBillType(e.target.value);
      saveStorage();
    });
  });

  // ── PAGE SIZE ──
  onInput('layoutPageSize', v => {
    S.bill.pageSize = v;
    updatePaperSize(v);
    saveStorage();
    checkOverflow();
  });

  // ── CHARGES ──
  onInput('calcHammaliNag',  v => { S.charges.hammaliNag  = parseFloat(v) || 0; recalcAndUpdate(); });
  onInput('calcHammaliRate', v => { S.charges.hammaliRate = parseFloat(v) || 0; recalcAndUpdate(); });
  // Legacy hidden field (read-only, updated by recalc)
  // onInput('calcHammali', ...) — no longer user-editable
  onInput('calcBori',    v => { S.charges.bori     = parseFloat(v) || 0; recalcAndUpdate(); });
  onInput('calcTaxGST',  v => { S.charges.gstRate  = parseFloat(v) || 0; recalcAndUpdate(); });
  onInput('calcAdvance', v => { S.charges.advance  = parseFloat(v) || 0; recalcAndUpdate(); });

  // ── ADD ITEM BUTTON ──
  el('btnAddRow')?.addEventListener('click', () => addItem());

  // ── CLEAR ITEMS BUTTON ──
  el('btnClearItems')?.addEventListener('click', () => {
    if (S.items.length === 0) return;
    if (confirm('सभी items हटाएं? (Are you sure?)')) {
      S.items = [];
      renderItemsTable();
      recalcAndUpdate();
      checkOverflow();
    }
  });

  // ── PRINT BUTTON ──
  el('btnPrint')?.addEventListener('click', async () => {
    // Validate: receiver name is required
    if (!S.bill.receiverName.trim()) {
      showToast('⚠️ खरीदार का नाम डालें, फिर Print करें।', 3500);
      // Switch to bill info tab
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      document.querySelector('[data-tab="tab-bill"]')?.classList.add('active');
      document.getElementById('tab-bill')?.classList.add('active');
      el('metaReceiverName')?.focus();
      return;
    }

    // 1. Save current invoice number before incrementing
    const savedInvoiceNo = S.bill.invoiceNo;

    // 2. Auto-increment invoice number
    if (S.bill.autoIncrement) {
      const n = parseInt(S.bill.invoiceNo);
      if (!isNaN(n)) {
        S.bill.invoiceNo = String(n + 1);
        const invoiceEl = el('metaInvoiceNo');
        if (invoiceEl) invoiceEl.value = S.bill.invoiceNo;
        const settingEl = el('settingNextNo');
        if (settingEl) settingEl.value = S.bill.invoiceNo;
        saveStorage();
        updateBillPreview();
      }
    }

    // 3. Save to Local Database BEFORE printing
    await saveBillRecord(savedInvoiceNo);
    showToast('✅ बिल save हो गया! Printing...');

    // 4. Print
    setTimeout(() => window.print(), 400);
  });

  // ── NEW BILL BUTTON ──
  el('btnNewBill')?.addEventListener('click', () => {
    if (!confirm('नया बिल शुरू करें? Items और Charges साफ हो जाएंगे।')) return;
    S.bill.id = null; // Reset bill ID for new bill
    S.items = [];
    S.bill.receiverName    = '';
    S.bill.receiverAddress = '';
    S.bill.vehicleInfo     = '';
    S.bill.date            = getToday();
    S.charges = { hammali: 0, hammaliNag: 0, hammaliRate: 0, bori: 0, gstRate: 0, advance: 0 };
    fillFormFromState();
    renderItemsTable();
    recalcAndUpdate();
    checkOverflow();
  });

  // ── SETTINGS: Auto-increment radio ──
  document.querySelectorAll('input[name="autoIncr"]').forEach(r => {
    r.addEventListener('change', e => {
      S.bill.autoIncrement = e.target.value === 'yes';
      saveStorage();
    });
  });

  // ── SETTINGS: Next bill number ──
  onInput('settingNextNo', v => {
    S.bill.invoiceNo = v;
    const invoiceEl = el('metaInvoiceNo');
    if (invoiceEl) invoiceEl.value = v;
    saveStorage();
    updateBillPreview();
  });

  // ── RESET ──
  el('btnReset')?.addEventListener('click', () => {
    if (confirm('सारा डेटा मिटाएं और app reset करें? यह वापस नहीं होगा।')) {
      localStorage.clear();
      location.reload();
    }
  });

  // ── LOGOUT ──
  // (wired dynamically in showUserInfo after auth resolves)

  // ── HISTORY: Search ──
  let histSearchTimeout;
  el('historySearch')?.addEventListener('input', e => {
    clearTimeout(histSearchTimeout);
    histSearchTimeout = setTimeout(() => loadBillHistory(e.target.value), 350);
  });

  // ── HISTORY: Refresh button ──
  el('btnRefreshHistory')?.addEventListener('click', () => {
    const q = el('historySearch')?.value || '';
    loadBillHistory(q);
  });

  // ── HISTORY: Switch to history tab triggers a load ──
  document.querySelectorAll('.tab-btn').forEach(btn => {
    if (btn.dataset.tab === 'tab-history') {
      btn.addEventListener('click', () => loadBillHistory(el('historySearch')?.value || ''));
    }
  });

  // ── EXPORT ──
  el('btnExport')?.addEventListener('click', exportJSON);

  // ── IMPORT ──
  el('btnImport')?.addEventListener('click', () => el('importFile')?.click());
  el('importFile')?.addEventListener('change', importJSON);
}

// ── Export state to JSON ──
function exportJSON() {
  const data = {
    profile: S.profile,
    bill:    S.bill,
    items:   S.items,
    charges: S.charges
  };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `Bill_${S.bill.invoiceNo}_${S.bill.date}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(a.href);
}

// ── Import state from JSON ──
function importJSON(e) {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = ev => {
    try {
      const data = JSON.parse(ev.target.result);
      if (!data.profile || !Array.isArray(data.items)) {
        alert('❌ Invalid file format.');
        return;
      }
      if (data.profile) S.profile = { ...S.profile, ...data.profile };
      if (data.bill)    S.bill    = { ...S.bill,    ...data.bill    };
      if (Array.isArray(data.items)) S.items = data.items;
      if (data.charges) S.charges = { ...S.charges, ...data.charges };

      saveStorage();
      fillFormFromState();
      renderItemsTable();
      recalcAndUpdate();
      applyBillType(S.bill.billType);
      updatePaperSize(S.bill.pageSize);
      checkOverflow();
      alert('✅ Data loaded successfully!');
    } catch (err) {
      alert('❌ Could not read file. Make sure it is a valid JSON file.');
      console.error(err);
    }
  };
  reader.readAsText(file);
  e.target.value = ''; // reset so same file can be re-imported
}

// ─────────────────────────────────────────────────────
//   BILL TEMPLATE SYSTEM
// ─────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────
//   BILL TEMPLATE SYSTEM (DYNAMIC)
// ─────────────────────────────────────────────────────
let ALL_TEMPLATE_CLASSES = [];

const DEFAULT_TEMPLATES = [
  {
    id: 'tmpl-1',
    name: 'Classic VYAPAR',
    previewCardStyle: '',
    previewHeadStyle: 'background:#e0e0e0; color:#333;',
    previewHeadText: '⚖️ VYAPAR',
    previewBodyHtml: '<div class="tp-line w70"></div><div class="tp-table"><div class="tp-tr"><div class="tp-td" style="background:#e8e8e8"></div><div class="tp-td"></div><div class="tp-td"></div></div><div class="tp-tr"><div class="tp-td"></div><div class="tp-td"></div><div class="tp-td"></div></div></div><div class="tp-line w50"></div>',
    css: '',
    isDefault: true
  },
  {
    id: 'tmpl-2',
    name: 'Simple Receipt',
    previewCardStyle: '',
    previewHeadStyle: 'background:#fff; color:#000; border-bottom:1px solid #111; font-size:8px;',
    previewHeadText: '📝 Simple Receipt',
    previewBodyHtml: '<div class="tp-line w70" style="background:#111; height:1px"></div><div class="tp-table" style="border-color:#111"><div class="tp-tr"><div class="tp-td" style="background:#f5f5f5"></div><div class="tp-td" style="background:#f5f5f5"></div></div><div class="tp-tr"><div class="tp-td"></div><div class="tp-td"></div></div></div><div class="tp-line w35" style="background:#888"></div>',
    css: '',
    isDefault: true
  },
  {
    id: 'tmpl-3',
    name: 'Bold Black',
    previewCardStyle: '',
    previewHeadStyle: 'background:#111; color:#fff; font-size:9px; letter-spacing:1px;',
    previewHeadText: 'VYAPAR',
    previewBodyHtml: '<div class="tp-line w70" style="background:#555"></div><div class="tp-table"><div class="tp-tr"><div class="tp-td" style="background:#f0f0f0"></div><div class="tp-td" style="background:#f0f0f0"></div><div class="tp-td" style="background:#f0f0f0"></div></div><div class="tp-tr"><div class="tp-td"></div><div class="tp-td"></div><div class="tp-td"></div></div></div><div class="tp-line w50" style="background:#111; height:3px"></div>',
    css: '',
    isDefault: true
  },
  {
    id: 'tmpl-4',
    name: 'Service Cursive',
    previewCardStyle: '',
    previewHeadStyle: 'background:#fff; color:#1a1a1a; font-family:Georgia,serif; font-style:italic; font-size:8px; border-bottom:1px solid #333;',
    previewHeadText: '✒️ Service Income',
    previewBodyHtml: '<div class="tp-line w70" style="background:#aaa; height:1px"></div><div class="tp-table" style="border-color:#333"><div class="tp-tr"><div class="tp-td" style="background:#f7f7f7"></div><div class="tp-td" style="background:#f7f7f7"></div></div><div class="tp-tr" style="border-bottom:1px dashed #ccc"><div class="tp-td"></div><div class="tp-td"></div></div></div><div class="tp-line w35" style="background:#bbb"></div>',
    css: '',
    isDefault: true
  },
  {
    id: 'tmpl-5',
    name: 'Credit Note',
    previewCardStyle: 'border:1.5px solid #c0392b; border-radius:0;',
    previewHeadStyle: 'background:#c0392b; color:#fff; font-size:9px; letter-spacing:0.5px;',
    previewHeadText: 'VYAPAR Credit Note',
    previewBodyHtml: '<div class="tp-line w70" style="background:#e57373"></div><div class="tp-table" style="border-color:#c0392b"><div class="tp-tr"><div class="tp-td" style="background:#ffeaea"></div><div class="tp-td" style="background:#ffeaea"></div><div class="tp-td" style="background:#ffeaea"></div></div><div class="tp-tr"><div class="tp-td"></div><div class="tp-td"></div><div class="tp-td"></div></div></div><div class="tp-line w50" style="background:#ffeaea; height:3px"></div>',
    css: '',
    isDefault: true
  },
  {
    id: 'tmpl-6',
    name: 'Wholesale Blue',
    previewCardStyle: 'border:1.5px solid #1a56db; border-radius:0;',
    previewHeadStyle: 'background:#1a56db; color:#fff; font-size:9px; letter-spacing:1px;',
    previewHeadText: 'A4/2 VYAPAR',
    previewBodyHtml: '<div class="tp-line w70" style="background:#93c5fd"></div><div class="tp-table" style="border-color:#1a56db"><div class="tp-tr"><div class="tp-td" style="background:#dbeafe"></div><div class="tp-td" style="background:#dbeafe"></div><div class="tp-td" style="background:#dbeafe"></div></div><div class="tp-tr"><div class="tp-td"></div><div class="tp-td"></div><div class="tp-td"></div></div></div><div class="tp-line w100" style="background:#1a56db; height:3px"></div>',
    css: '',
    isDefault: true
  },
  {
    id: 'tmpl-7',
    name: 'Grey Ledger',
    previewCardStyle: 'background:#fafafa;',
    previewHeadStyle: 'background:#9e9e9e; color:#fff; font-size:9px;',
    previewHeadText: 'VYAPAR',
    previewBodyHtml: '<div class="tp-line w70" style="background:#aaa"></div><div class="tp-table" style="border-color:#777"><div class="tp-tr"><div class="tp-td" style="background:#ddd"></div><div class="tp-td" style="background:#ddd"></div></div><div class="tp-tr"><div class="tp-td"></div><div class="tp-td"></div></div><div class="tp-tr" style="background:#f5f5f5"><div class="tp-td" style="background:#f0f0f0"></div><div class="tp-td" style="background:#f0f0f0"></div></div></div><div class="tp-line w50" style="background:#757575; height:3px"></div>',
    css: '',
    isDefault: true
  },
  {
    id: 'tmpl-8',
    name: 'Vintage Order',
    previewCardStyle: 'background:#fdf8ec; border:1px solid #c9b99a; border-radius:0;',
    previewHeadStyle: 'background:#f5e6c8; color:#3d2b1f; font-family:Georgia,serif; font-style:italic; border-bottom:1.5px solid #8b6914;',
    previewHeadText: '📜 Order Form',
    previewBodyHtml: '<div class="tp-line w70" style="background:#c9b99a"></div><div class="tp-table" style="border-color:#8b6914"><div class="tp-tr"><div class="tp-td" style="background:#f5e6c8"></div><div class="tp-td" style="background:#f5e6c8"></div></div><div class="tp-tr"><div class="tp-td"></div><div class="tp-td"></div></div></div><div class="tp-line w35" style="background:#8b6914"></div>',
    css: '',
    isDefault: true
  },
  {
    id: 'tmpl-9',
    name: 'Bold Blue VYAPAR',
    previewCardStyle: 'border:2px solid #1a56db; border-radius:0;',
    previewHeadStyle: 'background:#1a56db; color:#fff; font-size:10px; font-weight:900; letter-spacing:2px;',
    previewHeadText: 'VYAPAR',
    previewBodyHtml: '<div class="tp-line w70" style="background:#93c5fd"></div><div class="tp-table"><div class="tp-tr"><div class="tp-td" style="background:#1a56db; height:4px"></div><div class="tp-td" style="background:#1a56db; height:4px"></div><div class="tp-td" style="background:#1a56db; height:4px"></div></div><div class="tp-tr"><div class="tp-td"></div><div class="tp-td"></div><div class="tp-td"></div></div></div><div class="tp-line w100" style="background:#1340a0; height:4px"></div>',
    css: '',
    isDefault: true
  }
];

function getSavedTemplates() {
  const data = localStorage.getItem('bm_templates');
  if (!data) {
    localStorage.setItem('bm_templates', JSON.stringify(DEFAULT_TEMPLATES));
    return DEFAULT_TEMPLATES;
  }
  try {
    const parsed = JSON.parse(data);
    if (!parsed || !Array.isArray(parsed) || parsed.length === 0) {
      localStorage.setItem('bm_templates', JSON.stringify(DEFAULT_TEMPLATES));
      return DEFAULT_TEMPLATES;
    }
    return parsed;
  } catch (e) {
    console.error('Error parsing bm_templates', e);
    localStorage.setItem('bm_templates', JSON.stringify(DEFAULT_TEMPLATES));
    return DEFAULT_TEMPLATES;
  }
}

function selectTemplate(card) {
  const paper = document.getElementById('invoicePaper');
  if (!paper) return;

  // Remove any template classes that start with tmpl-
  for (let i = paper.classList.length - 1; i >= 0; i--) {
    const cls = paper.classList[i];
    if (cls && cls.startsWith('tmpl-')) {
      paper.classList.remove(cls);
    }
  }

  // Apply the chosen template
  const tmpl = card.dataset.tmpl || '';
  if (tmpl) paper.classList.add(tmpl);

  // Update active highlight on cards
  document.querySelectorAll('.tmpl-card').forEach(c => c.classList.remove('tmpl-active'));
  card.classList.add('tmpl-active');

  // Persist to localStorage
  localStorage.setItem('bm_active_template', tmpl);
  showToast('🎨 Template applied!');
}

function loadSavedTemplate() {
  let saved = localStorage.getItem('bm_active_template') || 'tmpl-1';
  if (!ALL_TEMPLATE_CLASSES.includes(saved)) {
    saved = 'tmpl-1';
    localStorage.setItem('bm_active_template', 'tmpl-1');
  }
  const paper = document.getElementById('invoicePaper');
  if (!paper) return;

  // Remove any template classes that start with tmpl-
  for (let i = paper.classList.length - 1; i >= 0; i--) {
    const cls = paper.classList[i];
    if (cls && cls.startsWith('tmpl-')) {
      paper.classList.remove(cls);
    }
  }
  if (saved) paper.classList.add(saved);

  // Mark correct card as active
  document.querySelectorAll('.tmpl-card').forEach(c => {
    const match = (c.dataset.tmpl || '') === saved;
    c.classList.toggle('tmpl-active', match);
  });
}

function renderTemplatesGrid() {
  const templates = getSavedTemplates();
  const grid = document.getElementById('templateGrid');
  if (!grid) return;

  grid.innerHTML = '';
  ALL_TEMPLATE_CLASSES = templates.map(t => t.id);

  // Inject custom CSS into page head
  const styleTag = document.getElementById('dynamicTemplatesCss');
  if (styleTag) {
    const customCssStr = templates
      .filter(t => t.css)
      .map(t => t.css)
      .join('\n');
    styleTag.textContent = customCssStr;
  }

  templates.forEach(t => {
    const card = document.createElement('div');
    card.className = 'tmpl-card';
    card.dataset.tmpl = t.id;
    if (t.previewCardStyle) {
      card.setAttribute('style', t.previewCardStyle);
    }
    
    card.addEventListener('click', () => selectTemplate(card));

    card.innerHTML = `
      <div class="tmpl-preview">
        <div class="tmpl-preview-head" style="${t.previewHeadStyle || ''}">${t.previewHeadText || ''}</div>
        <div class="tmpl-preview-body">
          ${t.previewBodyHtml || ''}
        </div>
      </div>
      <div class="tmpl-name">${t.name}</div>
    `;
    grid.appendChild(card);
  });
  
  loadSavedTemplate();
}

// Hook into page load to restore and render saved templates
document.addEventListener('DOMContentLoaded', () => {
  renderTemplatesGrid();
  // Listen for storage changes in case admin updates template from another tab
  window.addEventListener('storage', (e) => {
    if (e.key === 'bm_templates' || e.key === 'bm_active_template') {
      renderTemplatesGrid();
    }
  });
});
