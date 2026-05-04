function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
const {
  useState,
  useEffect,
  useRef,
  useMemo,
  createContext,
  useContext,
  useCallback
} = React;

// ==================== API Client ====================
const API_BASE = ''; // 同源，走 /api/*

async function apiCall(path, options = {}) {
  const token = localStorage.getItem('token');
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? {
      'Authorization': 'Bearer ' + token
    } : {}),
    ...(options.headers || {})
  };
  const resp = await fetch(API_BASE + path, {
    ...options,
    headers
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    const err = new Error(data.error || data.message || 'HTTP ' + resp.status);
    err.status = resp.status;
    err.data = data;
    throw err;
  }
  return data;
}

// ==================== Indicator（指南针 Logo） ====================
function Logo({
  size = 32,
  className = ''
}) {
  return /*#__PURE__*/React.createElement("svg", {
    xmlns: "http://www.w3.org/2000/svg",
    viewBox: "0 0 32 32",
    width: size,
    height: size,
    className: className
  }, /*#__PURE__*/React.createElement("circle", {
    cx: "16",
    cy: "16",
    r: "13",
    fill: "none",
    stroke: "#2563eb",
    strokeWidth: "2"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M16 7 L19 16 L16 25 L13 16 Z",
    fill: "#10b981"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "16",
    cy: "16",
    r: "1.5",
    fill: "#1a1a1a"
  }));
}

// ==================== 小图标（内联 SVG，避免引入图标库） ====================
const Icon = {
  Home: p => /*#__PURE__*/React.createElement("svg", _extends({
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, p), /*#__PURE__*/React.createElement("path", {
    d: "M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"
  }), /*#__PURE__*/React.createElement("polyline", {
    points: "9 22 9 12 15 12 15 22"
  })),
  Resume: p => /*#__PURE__*/React.createElement("svg", _extends({
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, p), /*#__PURE__*/React.createElement("path", {
    d: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"
  }), /*#__PURE__*/React.createElement("polyline", {
    points: "14 2 14 8 20 8"
  }), /*#__PURE__*/React.createElement("line", {
    x1: "8",
    y1: "13",
    x2: "16",
    y2: "13"
  }), /*#__PURE__*/React.createElement("line", {
    x1: "8",
    y1: "17",
    x2: "14",
    y2: "17"
  })),
  JD: p => /*#__PURE__*/React.createElement("svg", _extends({
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, p), /*#__PURE__*/React.createElement("rect", {
    x: "2",
    y: "7",
    width: "20",
    height: "14",
    rx: "2"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M16 7V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v2"
  })),
  Board: p => /*#__PURE__*/React.createElement("svg", _extends({
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, p), /*#__PURE__*/React.createElement("rect", {
    x: "3",
    y: "3",
    width: "7",
    height: "9"
  }), /*#__PURE__*/React.createElement("rect", {
    x: "14",
    y: "3",
    width: "7",
    height: "5"
  }), /*#__PURE__*/React.createElement("rect", {
    x: "14",
    y: "12",
    width: "7",
    height: "9"
  }), /*#__PURE__*/React.createElement("rect", {
    x: "3",
    y: "16",
    width: "7",
    height: "5"
  })),
  Profile: p => /*#__PURE__*/React.createElement("svg", _extends({
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, p), /*#__PURE__*/React.createElement("circle", {
    cx: "12",
    cy: "12",
    r: "10"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M12 6v6l4 2"
  })),
  Practice: p => /*#__PURE__*/React.createElement("svg", _extends({
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, p), /*#__PURE__*/React.createElement("path", {
    d: "M12 20h9"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"
  })),
  Review: p => /*#__PURE__*/React.createElement("svg", _extends({
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, p), /*#__PURE__*/React.createElement("path", {
    d: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"
  }), /*#__PURE__*/React.createElement("polyline", {
    points: "14 2 14 8 20 8"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M9 12l2 2 4-4"
  })),
  Suggestion: p => /*#__PURE__*/React.createElement("svg", _extends({
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, p), /*#__PURE__*/React.createElement("path", {
    d: "M9 18h6"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M10 22h4"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M15.09 14c.18-.98.65-1.74 1.41-2.5A4.65 4.65 0 0 0 18 8 6 6 0 0 0 6 8c0 1 .23 2.23 1.5 3.5A4.61 4.61 0 0 1 8.91 14"
  })),
  Bell: p => /*#__PURE__*/React.createElement("svg", _extends({
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, p), /*#__PURE__*/React.createElement("path", {
    d: "M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M13.73 21a2 2 0 0 1-3.46 0"
  })),
  Settings: p => /*#__PURE__*/React.createElement("svg", _extends({
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, p), /*#__PURE__*/React.createElement("circle", {
    cx: "12",
    cy: "12",
    r: "3"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"
  })),
  Admin: p => /*#__PURE__*/React.createElement("svg", _extends({
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, p), /*#__PURE__*/React.createElement("path", {
    d: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"
  })),
  Menu: p => /*#__PURE__*/React.createElement("svg", _extends({
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, p), /*#__PURE__*/React.createElement("line", {
    x1: "3",
    y1: "6",
    x2: "21",
    y2: "6"
  }), /*#__PURE__*/React.createElement("line", {
    x1: "3",
    y1: "12",
    x2: "21",
    y2: "12"
  }), /*#__PURE__*/React.createElement("line", {
    x1: "3",
    y1: "18",
    x2: "21",
    y2: "18"
  })),
  X: p => /*#__PURE__*/React.createElement("svg", _extends({
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, p), /*#__PURE__*/React.createElement("line", {
    x1: "18",
    y1: "6",
    x2: "6",
    y2: "18"
  }), /*#__PURE__*/React.createElement("line", {
    x1: "6",
    y1: "6",
    x2: "18",
    y2: "18"
  })),
  Plus: p => /*#__PURE__*/React.createElement("svg", _extends({
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, p), /*#__PURE__*/React.createElement("line", {
    x1: "12",
    y1: "5",
    x2: "12",
    y2: "19"
  }), /*#__PURE__*/React.createElement("line", {
    x1: "5",
    y1: "12",
    x2: "19",
    y2: "12"
  })),
  ArrowRight: p => /*#__PURE__*/React.createElement("svg", _extends({
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, p), /*#__PURE__*/React.createElement("line", {
    x1: "5",
    y1: "12",
    x2: "19",
    y2: "12"
  }), /*#__PURE__*/React.createElement("polyline", {
    points: "12 5 19 12 12 19"
  })),
  Info: p => /*#__PURE__*/React.createElement("svg", _extends({
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, p), /*#__PURE__*/React.createElement("circle", {
    cx: "12",
    cy: "12",
    r: "10"
  }), /*#__PURE__*/React.createElement("line", {
    x1: "12",
    y1: "16",
    x2: "12",
    y2: "12"
  }), /*#__PURE__*/React.createElement("line", {
    x1: "12",
    y1: "8",
    x2: "12.01",
    y2: "8"
  })),
  Wall: p => /*#__PURE__*/React.createElement("svg", _extends({
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, p), /*#__PURE__*/React.createElement("line", {
    x1: "4",
    y1: "21",
    x2: "4",
    y2: "3"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M4 3l16 0c1.1 0 2 .9 2 2l0 4c0 1.1-.9 2-2 2l-10 0l-8 0"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M4 11l16 0"
  }))
};

// ==================== 全局应用上下文 ====================
const AppContext = createContext(null);
const useApp = () => useContext(AppContext);
function AppProvider({
  children
}) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [toasts, setToasts] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [route, setRoute] = useState(() => {
    return window.location.hash.slice(1) || 'home';
  });

  // 路由变化监听
  useEffect(() => {
    const handler = () => setRoute(window.location.hash.slice(1) || 'home');
    window.addEventListener('hashchange', handler);
    return () => window.removeEventListener('hashchange', handler);
  }, []);
  const navigate = useCallback(path => {
    window.location.hash = path;
  }, []);

  // Toast 系统
  const toast = useCallback((message, type = 'info', duration = 3000) => {
    const id = Date.now() + Math.random();
    setToasts(ts => [...ts, {
      id,
      message,
      type
    }]);
    if (duration > 0) {
      setTimeout(() => {
        setToasts(ts => ts.filter(t => t.id !== id));
      }, duration);
    }
    return id;
  }, []);
  const dismissToast = useCallback(id => {
    setToasts(ts => ts.filter(t => t.id !== id));
  }, []);

  // 初始化：注册/登录指纹账号
  useEffect(() => {
    const safeSet = (k, v) => {
      try {
        localStorage.setItem(k, v);
      } catch {}
    };
    const safeGet = k => {
      try {
        return localStorage.getItem(k);
      } catch {
        return null;
      }
    };
    const safeDel = k => {
      try {
        localStorage.removeItem(k);
      } catch {}
    };
    async function init() {
      try {
        let fp = safeGet('fingerprint');
        if (!fp) {
          fp = 'fp_' + Math.random().toString(36).slice(2) + Date.now().toString(36);
          safeSet('fingerprint', fp);
        }
        let token = safeGet('token');
        if (token) {
          // 尝试用老 token 拿 user
          try {
            const r = await apiCall('/api/auth/me');
            setUser(r.user);
            setLoading(false);
            return;
          } catch {
            // token 失效，走注册
            safeDel('token');
          }
        }

        // 指纹注册/登录
        const r = await apiCall('/api/auth/anon', {
          method: 'POST',
          body: JSON.stringify({
            fingerprint: fp
          })
        });
        safeSet('token', r.token);
        safeSet('user_id', r.user.id);
        setUser(r.user);
      } catch (e) {
        toast('连接失败：' + e.message, 'error', 5000);
      }
      setLoading(false);
    }
    init();
  }, []);

  // 拉通知未读数（每 60s 一次）
  useEffect(() => {
    if (!user) return;
    let timer;
    async function fetchUnread() {
      try {
        const r = await apiCall('/api/notifications?unread=1&limit=1');
        setUnreadCount(r.unread_count || 0);
      } catch {}
    }
    fetchUnread();
    timer = setInterval(fetchUnread, 60000);
    return () => clearInterval(timer);
  }, [user]);
  const refreshUser = useCallback(async () => {
    try {
      const r = await apiCall('/api/auth/me');
      setUser(r.user);
    } catch {}
  }, []);
  const value = {
    user,
    setUser,
    loading,
    toast,
    dismissToast,
    toasts,
    route,
    navigate,
    unreadCount,
    refreshUser
  };
  return /*#__PURE__*/React.createElement(AppContext.Provider, {
    value: value
  }, children);
}

// ==================== Toast 组件 ====================
function ToastStack() {
  const {
    toasts,
    dismissToast
  } = useApp();
  return /*#__PURE__*/React.createElement("div", {
    className: "fixed top-4 right-4 z-50 flex flex-col gap-2 pointer-events-none"
  }, toasts.map(t => /*#__PURE__*/React.createElement("div", {
    key: t.id,
    className: 'pointer-events-auto animate-toast-in px-4 py-3 rounded-xl shadow-lifted text-sm font-medium min-w-[260px] max-w-[360px] flex items-start gap-2 ' + (t.type === 'error' ? 'bg-rose-50 text-rose-900 border border-rose-200' : t.type === 'success' ? 'bg-emerald-50 text-emerald-900 border border-emerald-200' : 'bg-white text-gray-900 border border-gray-200')
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex-1"
  }, t.message), /*#__PURE__*/React.createElement("button", {
    onClick: () => dismissToast(t.id),
    className: "opacity-50 hover:opacity-100 transition"
  }, /*#__PURE__*/React.createElement(Icon.X, {
    className: "w-4 h-4"
  })))));
}

// ==================== 换设备提醒小弹窗 ====================
function DeviceNoticeBubble() {
  const [show, setShow] = useState(() => {
    return !localStorage.getItem('device_notice_dismissed');
  });
  if (!show) return null;
  const handleDismiss = () => {
    localStorage.setItem('device_notice_dismissed', '1');
    setShow(false);
  };
  return /*#__PURE__*/React.createElement("div", {
    className: "fixed top-20 right-4 z-40 w-[320px] animate-slide-up"
  }, /*#__PURE__*/React.createElement("div", {
    className: "bg-white rounded-xl shadow-float border border-amber-200 p-4"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-start gap-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "mt-0.5 w-8 h-8 rounded-full bg-amber-50 flex items-center justify-center flex-shrink-0"
  }, /*#__PURE__*/React.createElement(Icon.Info, {
    className: "w-4 h-4 text-amber-600"
  })), /*#__PURE__*/React.createElement("div", {
    className: "flex-1 min-w-0"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-sm font-semibold text-gray-900"
  }, "\u5173\u4E8E\u6362\u8BBE\u5907"), /*#__PURE__*/React.createElement("div", {
    className: "mt-1 text-xs text-gray-600 leading-relaxed"
  }, "\u76EE\u524D\u6362\u8BBE\u5907\u767B\u5F55\u4F1A\u521B\u5EFA\u65B0\u8D26\u53F7\uFF0C\u6570\u636E\u4E0D\u4E92\u901A\u3002\u90AE\u7BB1\u7ED1\u5B9A\u6062\u590D\u529F\u80FD\u6B63\u5728\u5F00\u53D1\u4E2D\uFF0C\u5EFA\u8BAE\u957F\u671F\u4F7F\u7528\u540C\u4E00\u8BBE\u5907\u3002")), /*#__PURE__*/React.createElement("button", {
    onClick: handleDismiss,
    className: "flex-shrink-0 text-gray-400 hover:text-gray-700 transition"
  }, /*#__PURE__*/React.createElement(Icon.X, {
    className: "w-4 h-4"
  })))));
}

// ==================== Layout: 顶部栏 + 左侧边栏 ====================
function Layout({
  children
}) {
  const {
    user,
    unreadCount,
    navigate,
    route
  } = useApp();
  const [sidebarOpen, setSidebarOpen] = useState(false); // 移动端

  const menu = [{
    key: 'home',
    label: '总览',
    icon: Icon.Home
  }, {
    key: 'resumes',
    label: '简历',
    icon: Icon.Resume
  }, {
    key: 'jds',
    label: 'JD 库',
    icon: Icon.JD
  }, {
    key: 'positions',
    label: '岗位看板',
    icon: Icon.Board
  }, {
    key: 'reviews',
    label: '复盘',
    icon: Icon.Review
  }, {
    key: 'profile',
    label: '我的画像',
    icon: Icon.Profile
  }, {
    key: 'practice',
    label: '陪练题',
    icon: Icon.Practice
  }, {
    key: 'suggestions',
    label: 'AI 建议',
    icon: Icon.Suggestion
  }, {
    key: 'wall',
    label: '面经墙',
    icon: Icon.Wall
  }, {
    key: 'notifications',
    label: '通知',
    icon: Icon.Bell,
    badge: unreadCount
  }, {
    key: 'settings',
    label: '设置',
    icon: Icon.Settings
  }];
  if (user?.is_admin) {
    menu.push({
      key: 'admin',
      label: '管理面板',
      icon: Icon.Admin
    });
  }
  const currentRoot = route.split('/')[0] || 'home';
  return /*#__PURE__*/React.createElement("div", {
    className: "min-h-screen flex flex-col"
  }, /*#__PURE__*/React.createElement("header", {
    className: "sticky top-0 z-30 bg-white/80 backdrop-blur-md border-b border-gray-200"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center h-14 px-4"
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => setSidebarOpen(true),
    className: "md:hidden p-2 -ml-2 text-gray-600 hover:text-gray-900 transition"
  }, /*#__PURE__*/React.createElement(Icon.Menu, {
    className: "w-5 h-5"
  })), /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-2.5 cursor-pointer",
    onClick: () => navigate('home')
  }, /*#__PURE__*/React.createElement(Logo, {
    size: 28
  }), /*#__PURE__*/React.createElement("div", {
    className: "hidden sm:block"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-[15px] font-semibold text-gray-900 leading-tight"
  }, "\u6C42\u804C\u5C0F\u52A9"), /*#__PURE__*/React.createElement("div", {
    className: "text-[10px] text-gray-500 leading-tight"
  }, "AI \u966A\u8DD1\u7BA1\u5BB6"))), /*#__PURE__*/React.createElement("div", {
    className: "flex-1"
  }), user && /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-3"
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => navigate('notifications'),
    className: "relative p-2 rounded-lg text-gray-600 hover:text-gray-900 hover:bg-gray-100 btn-apple"
  }, /*#__PURE__*/React.createElement(Icon.Bell, {
    className: "w-5 h-5"
  }), unreadCount > 0 && /*#__PURE__*/React.createElement("span", {
    className: "absolute top-1 right-1 w-4 h-4 rounded-full bg-rose-500 text-white text-[10px] font-bold flex items-center justify-center animate-scale-in badge-pulse"
  }, unreadCount > 9 ? '9+' : unreadCount)), /*#__PURE__*/React.createElement("div", {
    className: "hidden sm:flex items-center gap-2 text-sm"
  }, /*#__PURE__*/React.createElement("div", {
    className: "w-7 h-7 rounded-full bg-gradient-to-br from-brand-500 to-accent-500 flex items-center justify-center text-white text-xs font-semibold"
  }, (user.name || 'U').slice(0, 1).toUpperCase()), /*#__PURE__*/React.createElement("span", {
    className: "text-gray-700"
  }, user.name || '未设置名字'))))), /*#__PURE__*/React.createElement("div", {
    className: "flex-1 flex"
  }, sidebarOpen && /*#__PURE__*/React.createElement("div", {
    className: "fixed inset-0 bg-black/40 z-40 md:hidden animate-fade-in",
    onClick: () => setSidebarOpen(false)
  }), /*#__PURE__*/React.createElement("aside", {
    className: 'bg-white border-r border-gray-200 w-[220px] flex-shrink-0 z-40 flex flex-col ' + 'md:sticky md:top-14 md:self-start md:h-[calc(100vh-3.5rem)] ' + 'fixed top-14 bottom-0 left-0 transition-transform duration-300 ' + (sidebarOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0')
  }, /*#__PURE__*/React.createElement("nav", {
    className: "p-3 flex flex-col gap-0.5 flex-1"
  }, menu.map(item => {
    const IconComp = item.icon;
    const active = currentRoot === item.key;
    return /*#__PURE__*/React.createElement("button", {
      key: item.key,
      onClick: () => {
        navigate(item.key);
        setSidebarOpen(false);
      },
      className: 'group flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium btn-apple ' + (active ? 'bg-brand-50 text-brand-700' : 'text-gray-700 hover:bg-gray-100')
    }, /*#__PURE__*/React.createElement(IconComp, {
      className: 'w-[18px] h-[18px] ' + (active ? 'text-brand-600' : 'text-gray-500 group-hover:text-gray-700')
    }), /*#__PURE__*/React.createElement("span", {
      className: "flex-1 text-left"
    }, item.label), item.badge > 0 && /*#__PURE__*/React.createElement("span", {
      className: "min-w-[18px] h-[18px] px-1 rounded-full bg-rose-500 text-white text-[10px] font-bold flex items-center justify-center"
    }, item.badge > 9 ? '9+' : item.badge));
  })), /*#__PURE__*/React.createElement("div", {
    className: "px-4 py-3 border-t border-gray-100 text-[11px] text-gray-400 leading-tight"
  }, "by dxh \u540C\u5B66", /*#__PURE__*/React.createElement("span", {
    className: "mx-1.5 text-gray-300"
  }, "\xB7"), "v3.3")), /*#__PURE__*/React.createElement("main", {
    className: "flex-1 min-w-0"
  }, /*#__PURE__*/React.createElement("div", {
    className: "max-w-6xl mx-auto px-4 md:px-8 py-6 md:py-8 animate-page-enter"
  }, children))));
}

// ==================== 引导卡牌 Onboarding v3.2 ====================
function OnboardingFlow({
  onDone
}) {
  const {
    toast,
    refreshUser
  } = useApp();
  const [step, setStep] = useState(0);
  const [leaving, setLeaving] = useState(false);
  const [form, setForm] = useState({
    name: '',
    target_track: '',
    school: '',
    graduation_year: ''
  });
  const [submitting, setSubmitting] = useState(false);
  const skip = () => {
    setLeaving(true);
    localStorage.setItem('onboarding_dismissed', '1');
    setTimeout(onDone, 250);
  };
  const submit = async () => {
    setSubmitting(true);
    try {
      await apiCall('/api/auth/onboard', {
        method: 'POST',
        body: JSON.stringify({
          name: form.name || null,
          target_track: form.target_track || null,
          school: form.school || null,
          graduation_year: form.graduation_year ? Number(form.graduation_year) : null
        })
      });
      await refreshUser();
      toast('设置完成，开始使用吧', 'success');
      setLeaving(true);
      setTimeout(onDone, 250);
    } catch (e) {
      toast('保存失败：' + e.message, 'error');
    }
    setSubmitting(false);
  };
  const cards = [
  // 1. 总览
  {
    icon: '🧭',
    title: '你的 AI 求职陪跑管家',
    body: /*#__PURE__*/React.createElement("div", {
      className: "text-sm text-gray-700 leading-relaxed space-y-3"
    }, /*#__PURE__*/React.createElement("p", null, "\u4E00\u4E2A\u966A\u4F60\u8D70\u5B8C\u6574\u4E2A\u6C42\u804C\u5468\u671F\u7684 AI \u5DE5\u5177\u2014\u2014", /*#__PURE__*/React.createElement("strong", null, "\u6295\u9012\u524D \u2192 \u9762\u8BD5\u524D \u2192 \u9762\u8BD5\u540E"), "\uFF0C\u6BCF\u4E00\u6B65\u90FD\u6709\u5B83\u3002"), /*#__PURE__*/React.createElement("div", {
      className: "grid grid-cols-2 gap-2"
    }, [{
      emoji: '📋',
      label: 'JD 匹配',
      desc: '粘贴简历+JD，秒看匹配度'
    }, {
      emoji: '🎯',
      label: 'AI 陪练',
      desc: '简历深挖 + 真实面经题'
    }, {
      emoji: '🧠',
      label: '面试复盘',
      desc: '粘贴回忆，AI 帮你分析'
    }, {
      emoji: '🔄',
      label: '个人画像',
      desc: '越用越懂你，建议越来越准'
    }].map((item, i) => /*#__PURE__*/React.createElement("div", {
      key: i,
      className: "bg-gray-50 rounded-xl p-3 border border-gray-100 hover:border-brand-200 transition-colors"
    }, /*#__PURE__*/React.createElement("div", {
      className: "text-lg mb-1"
    }, item.emoji), /*#__PURE__*/React.createElement("div", {
      className: "text-xs font-semibold text-gray-800"
    }, item.label), /*#__PURE__*/React.createElement("div", {
      className: "text-[10px] text-gray-500 mt-0.5"
    }, item.desc)))), /*#__PURE__*/React.createElement("p", {
      className: "text-[10px] text-gray-400"
    }, "\u4E0D\u7528\u4E0B\u8F7D\uFF0C\u4E0D\u7528\u6CE8\u518C\uFF0C\u6D4F\u89C8\u5668\u6253\u5F00\u5C31\u662F\u4F60\u7684"))
  },
  // 2. JD 匹配
  {
    icon: '📋',
    title: '粘贴 JD，秒懂匹配度',
    body: /*#__PURE__*/React.createElement("div", {
      className: "text-sm text-gray-700 leading-relaxed space-y-3"
    }, /*#__PURE__*/React.createElement("p", null, "\u5047\u8BBE\u4F60\u521A\u5728\u62DB\u8058\u7F51\u7AD9\u4E0A\u770B\u5230\u4E86\u4E00\u4E2A\u5FC3\u4EEA\u7684\u4EA7\u54C1\u5B9E\u4E60\u5C97\u2014\u2014"), /*#__PURE__*/React.createElement("div", {
      className: "bg-brand-50 rounded-xl p-3.5 text-xs text-brand-800 border border-brand-100 space-y-1.5"
    }, /*#__PURE__*/React.createElement("p", null, "\u628A JD \u7C98\u8D34\u8FDB\u6765 \u2192 AI ", /*#__PURE__*/React.createElement("strong", null, "\u81EA\u52A8\u62C6\u89E3"), "\u5C97\u4F4D\u8981\u6C42"), /*#__PURE__*/React.createElement("div", {
      className: "flex items-center gap-2 text-gray-500"
    }, /*#__PURE__*/React.createElement("span", {
      className: "w-1 h-1 rounded-full bg-brand-400"
    }), /*#__PURE__*/React.createElement("span", null, "\u5BF9\u6BD4\u4F60\u7684\u7B80\u5386\uFF0C\u627E\u51FA", /*#__PURE__*/React.createElement("strong", null, "\u5339\u914D\u70B9"))), /*#__PURE__*/React.createElement("div", {
      className: "flex items-center gap-2 text-gray-500"
    }, /*#__PURE__*/React.createElement("span", {
      className: "w-1 h-1 rounded-full bg-amber-400"
    }), /*#__PURE__*/React.createElement("span", null, "\u6807\u8BB0", /*#__PURE__*/React.createElement("strong", null, "\u5DEE\u8DDD\u9879"), "\uFF0C\u544A\u8BC9\u4F60\u5DEE\u5728\u54EA\u513F")), /*#__PURE__*/React.createElement("div", {
      className: "flex items-center gap-2 text-green-600"
    }, /*#__PURE__*/React.createElement("span", {
      className: "w-1 h-1 rounded-full bg-green-500"
    }), /*#__PURE__*/React.createElement("span", null, "\u7ED9\u51FA\u9488\u5BF9\u6027", /*#__PURE__*/React.createElement("strong", null, "\u6539\u8FDB\u5EFA\u8BAE")))))
  },
  // 3. JD 分析
  {
    icon: '📊',
    title: '不只是打分的 JD 分析',
    body: /*#__PURE__*/React.createElement("div", {
      className: "text-sm text-gray-700 leading-relaxed space-y-3"
    }, /*#__PURE__*/React.createElement("p", null, "AI \u4F1A\u7ED9\u6BCF\u4E2A JD \u6253\u51FA", /*#__PURE__*/React.createElement("strong", {
      className: "text-brand-700"
    }, "6 \u6863\u5339\u914D\u8BC4\u5206"), "\uFF0C\u66F4\u5173\u952E\u7684\u662F\u2014\u2014"), /*#__PURE__*/React.createElement("div", {
      className: "bg-amber-50 rounded-xl p-3.5 border border-amber-100 space-y-2"
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex items-center gap-2"
    }, /*#__PURE__*/React.createElement("div", {
      className: "w-10 h-10 rounded-full bg-amber-100 flex items-center justify-center text-lg font-bold text-amber-700"
    }, "78"), /*#__PURE__*/React.createElement("div", {
      className: "text-xs text-amber-800"
    }, /*#__PURE__*/React.createElement("strong", null, "\u5339\u914D\u5EA6 78%\uFF08\u4E2D\u7B49\u504F\u4E0A\uFF09"))), /*#__PURE__*/React.createElement("div", {
      className: "text-[11px] space-y-1 text-amber-700 pl-1"
    }, /*#__PURE__*/React.createElement("div", null, "\u2705 \u300C\u7528\u6237\u8C03\u7814\u300D\u7ECF\u5386\u662F\u52A0\u5206\u9879"), /*#__PURE__*/React.createElement("div", null, "\u26A0\uFE0F \u300C\u6570\u636E\u5206\u6790\u300D\u662F\u7B80\u5386\u7F3A\u5931\u7684\u5173\u952E\u8BCD"), /*#__PURE__*/React.createElement("div", null, "\uD83D\uDCA1 \u5EFA\u8BAE\u9762\u8BD5\u524D\u91CD\u70B9\u8865\u5145\u6570\u636E\u76F8\u5173\u8868\u8FBE"))))
  },
  // 4. AI 陪练（新增）
  {
    icon: '🎯',
    title: '面试前的 AI 陪练',
    body: /*#__PURE__*/React.createElement("div", {
      className: "text-sm text-gray-700 leading-relaxed space-y-3"
    }, /*#__PURE__*/React.createElement("p", null, "\u9009\u5B9A\u76EE\u6807\u5C97\u4F4D\u540E\uFF0CAI \u4ECE", /*#__PURE__*/React.createElement("strong", null, "\u4E24\u4E2A\u65B9\u5411"), "\u5E2E\u4F60\u51FA\u9898\uFF1A"), /*#__PURE__*/React.createElement("div", {
      className: "space-y-2"
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex gap-2.5"
    }, /*#__PURE__*/React.createElement("div", {
      className: "w-8 h-8 rounded-lg bg-brand-50 flex items-center justify-center text-sm flex-shrink-0"
    }, "\uD83E\uDD16"), /*#__PURE__*/React.createElement("div", {
      className: "bg-brand-50/50 rounded-lg px-3 py-2.5 flex-1 text-xs text-brand-800 border border-brand-100"
    }, /*#__PURE__*/React.createElement("strong", null, "AI \u7B80\u5386\u6DF1\u6316"), /*#__PURE__*/React.createElement("br", null), /*#__PURE__*/React.createElement("span", {
      className: "text-gray-600"
    }, "\u8BFB\u4F60\u7684\u7B80\u5386\uFF0C\u627E\u5230\u9762\u8BD5\u5B98\u6700\u5BB9\u6613\u8FFD\u95EE\u7684\u7EC6\u8282\u2014\u2014", /*#__PURE__*/React.createElement("em", null, "\u300C\u5B9E\u4E60\u91CC\u90A3\u4E2A\u589E\u957F\u6A21\u578B\uFF0C\u6570\u636E\u600E\u4E48\u9A8C\u8BC1\u7684\uFF1F\u300D")))), /*#__PURE__*/React.createElement("div", {
      className: "flex justify-center"
    }, /*#__PURE__*/React.createElement("svg", {
      className: "w-4 h-4 text-gray-300",
      viewBox: "0 0 24 24",
      fill: "none",
      stroke: "currentColor",
      strokeWidth: "2"
    }, /*#__PURE__*/React.createElement("line", {
      x1: "12",
      y1: "5",
      x2: "12",
      y2: "19"
    }), /*#__PURE__*/React.createElement("polyline", {
      points: "19 12 12 19 5 12"
    }))), /*#__PURE__*/React.createElement("div", {
      className: "flex gap-2.5"
    }, /*#__PURE__*/React.createElement("div", {
      className: "w-8 h-8 rounded-lg bg-green-50 flex items-center justify-center text-sm flex-shrink-0"
    }, "\uD83D\uDD0D"), /*#__PURE__*/React.createElement("div", {
      className: "bg-green-50/50 rounded-lg px-3 py-2.5 flex-1 text-xs text-green-800 border border-green-100"
    }, /*#__PURE__*/React.createElement("strong", null, "\u5168\u7F51\u771F\u5B9E\u9762\u7ECF"), /*#__PURE__*/React.createElement("br", null), /*#__PURE__*/React.createElement("span", {
      className: "text-gray-600"
    }, "\u641C\u725B\u5BA2/\u5C0F\u7EA2\u4E66/\u77E5\u4E4E\u4E0A", /*#__PURE__*/React.createElement("strong", null, "\u8FD9\u5BB6\u516C\u53F8\u8FD9\u4E2A\u5C97\u4F4D"), "\u7684\u771F\u5B9E\u9898\u76EE\uFF0C\u8FC7\u6EE4\u6CDB\u9898")))), /*#__PURE__*/React.createElement("p", {
      className: "text-[10px] text-gray-400"
    }, "\u4E24\u9053\u6765\u6E90\u81EA\u52A8\u5408\u5E76\uFF0C\u6BCF\u9053\u9898\u9644\u53C2\u8003\u8981\u70B9\u2014\u2014\u4E0D\u662F\u901A\u7528\u9898\u5E93\uFF0C\u662F\u4E13\u5C5E\u4F60\u7684"))
  },
  // 5. 复盘
  {
    icon: '🧠',
    title: '面试后的 AI 复盘',
    body: /*#__PURE__*/React.createElement("div", {
      className: "text-sm text-gray-700 leading-relaxed space-y-3"
    }, /*#__PURE__*/React.createElement("p", null, "\u9762\u5B8C\u5FC3\u4EEA\u7684\u516C\u53F8\uFF0C\u628A\u80FD\u8BB0\u8D77\u6765\u7684", /*#__PURE__*/React.createElement("strong", {
      className: "text-brand-700"
    }, "\u95EE\u7B54\u5BF9\u8BDD\u7C98\u8D34\u8FDB\u6765"), "\u2014\u2014"), /*#__PURE__*/React.createElement("div", {
      className: "bg-purple-50 rounded-xl p-3.5 border border-purple-100 space-y-2"
    }, /*#__PURE__*/React.createElement("div", {
      className: "text-xs text-purple-800"
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex items-center gap-1.5 mb-1.5"
    }, /*#__PURE__*/React.createElement("span", {
      className: "text-purple-500 text-[10px] font-semibold uppercase tracking-wide"
    }, "AI \u590D\u76D8"), /*#__PURE__*/React.createElement("span", {
      className: "w-px h-3 bg-purple-200"
    }), /*#__PURE__*/React.createElement("span", {
      className: "text-[10px] text-purple-400"
    }, "\u6574\u4F53 7/10")), /*#__PURE__*/React.createElement("div", {
      className: "space-y-1.5"
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex items-start gap-1.5"
    }, /*#__PURE__*/React.createElement("span", {
      className: "text-green-600 mt-0.5"
    }, "\u2705"), /*#__PURE__*/React.createElement("span", null, "\u300C\u9879\u76EE\u7ECF\u5386\u300D\u8BB2\u5F97\u624E\u5B9E\uFF0C\u6709\u6570\u636E\u6709\u903B\u8F91")), /*#__PURE__*/React.createElement("div", {
      className: "flex items-start gap-1.5"
    }, /*#__PURE__*/React.createElement("span", {
      className: "text-amber-600 mt-0.5"
    }, "\u26A0\uFE0F"), /*#__PURE__*/React.createElement("span", null, "\u88AB\u95EE\u5230", /*#__PURE__*/React.createElement("strong", null, "\u300C\u6307\u6807\u6389\u4E86\u600E\u4E48\u6392\u67E5\u300D"), "\u2014\u2014\u53EA\u8BF4\u4E86\u6570\u636E\u65B9\u6CD5\uFF0C\u6CA1\u5148\u505A\u4E1A\u52A1\u5F52\u56E0\uFF08\u5148\u5206\u4EA7\u54C1\u4FA7/\u6E20\u9053\u4FA7/\u5916\u90E8\u56E0\u7D20\uFF09")), /*#__PURE__*/React.createElement("div", {
      className: "flex items-start gap-1.5"
    }, /*#__PURE__*/React.createElement("span", {
      className: "text-blue-600 mt-0.5"
    }, "\uD83D\uDCA1"), /*#__PURE__*/React.createElement("span", null, "\u4E0B\u6B21\u5F52\u56E0\u7C7B\u95EE\u9898\uFF0C\u5148\u8BF4", /*#__PURE__*/React.createElement("strong", null, "\u300C\u6211\u5148\u4ECE\u4E09\u4E2A\u7EF4\u5EA6\u6392\u67E5\u300D"), "\u518D\u5C55\u5F00"))))))
  },
  // 6. 画像
  {
    icon: '🔄',
    title: '越用越懂你的画像系统',
    body: /*#__PURE__*/React.createElement("div", {
      className: "text-sm text-gray-700 leading-relaxed space-y-3"
    }, /*#__PURE__*/React.createElement("div", {
      className: "grid grid-cols-2 gap-2 text-xs"
    }, /*#__PURE__*/React.createElement("div", {
      className: "bg-gray-50 rounded-xl p-3 border border-gray-100"
    }, /*#__PURE__*/React.createElement("div", {
      className: "text-gray-400 mb-1.5"
    }, "\u7B2C 1 \u6B21\u4F7F\u7528"), /*#__PURE__*/React.createElement("div", {
      className: "flex flex-wrap gap-1"
    }, /*#__PURE__*/React.createElement("span", {
      className: "inline-block px-1.5 py-0.5 rounded bg-brand-100 text-brand-700 text-[10px]"
    }, "\u5B66\u6821/\u4E13\u4E1A"), /*#__PURE__*/React.createElement("span", {
      className: "inline-block px-1.5 py-0.5 rounded bg-brand-100 text-brand-700 text-[10px]"
    }, "\u6C42\u804C\u65B9\u5411"))), /*#__PURE__*/React.createElement("div", {
      className: "bg-brand-50 rounded-xl p-3 border border-brand-100"
    }, /*#__PURE__*/React.createElement("div", {
      className: "text-gray-400 mb-1.5"
    }, "\u7B2C 5 \u6B21\u4F7F\u7528"), /*#__PURE__*/React.createElement("div", {
      className: "flex flex-wrap gap-1"
    }, /*#__PURE__*/React.createElement("span", {
      className: "inline-block px-1.5 py-0.5 rounded bg-emerald-100 text-emerald-700 text-[10px]"
    }, "\u7ADE\u54C1\u5206\u6790"), /*#__PURE__*/React.createElement("span", {
      className: "inline-block px-1.5 py-0.5 rounded bg-emerald-100 text-emerald-700 text-[10px]"
    }, "\u7528\u6237\u6D1E\u5BDF"), /*#__PURE__*/React.createElement("span", {
      className: "inline-block px-1.5 py-0.5 rounded bg-amber-100 text-amber-700 text-[10px]"
    }, "\u6280\u672F\u7406\u89E3\u504F\u5F31")))), /*#__PURE__*/React.createElement("p", {
      className: "text-xs text-gray-500"
    }, "AI \u4F1A\u6301\u7EED\u4ECE\u4F60\u7684", /*#__PURE__*/React.createElement("strong", null, "\u7B80\u5386\u2192JD\u2192\u9762\u8BD5\u590D\u76D8"), "\u4E2D\u5B66\u4E60\uFF0C\u5339\u914D\u5EFA\u8BAE\u8D8A\u6765\u8D8A\u4E2A\u6027\u5316\u3002"))
  },
  // 7. 准备
  {
    icon: '🚀',
    title: '准备好了吗？',
    body: /*#__PURE__*/React.createElement("div", {
      className: "space-y-4"
    }, /*#__PURE__*/React.createElement("button", {
      onClick: skip,
      className: "w-full py-3 rounded-xl bg-gradient-to-r from-brand-500 to-brand-600 text-white text-sm font-semibold hover:from-brand-600 hover:to-brand-700 btn-apple shadow-soft"
    }, "\u5148\u53BB\u9996\u9875\u770B\u770B \u2192"), /*#__PURE__*/React.createElement("div", {
      className: "relative"
    }, /*#__PURE__*/React.createElement("div", {
      className: "absolute inset-0 flex items-center"
    }, /*#__PURE__*/React.createElement("div", {
      className: "w-full border-t border-gray-200"
    })), /*#__PURE__*/React.createElement("div", {
      className: "relative flex justify-center text-xs"
    }, /*#__PURE__*/React.createElement("span", {
      className: "bg-white px-3 text-gray-400"
    }, "\u6216\u8005"))), /*#__PURE__*/React.createElement("div", {
      className: "space-y-2.5"
    }, /*#__PURE__*/React.createElement("input", {
      className: "w-full px-3 py-2.5 rounded-lg border border-gray-200 text-sm",
      placeholder: "\u4F60\u7684\u540D\u5B57",
      value: form.name,
      onChange: e => setForm({
        ...form,
        name: e.target.value
      })
    }), /*#__PURE__*/React.createElement("select", {
      className: "w-full px-3 py-2.5 rounded-lg border border-gray-200 text-sm bg-white",
      value: form.target_track,
      onChange: e => setForm({
        ...form,
        target_track: e.target.value
      })
    }, /*#__PURE__*/React.createElement("option", {
      value: ""
    }, "\u6C42\u804C\u65B9\u5411\uFF08\u9009\u586B\uFF09"), /*#__PURE__*/React.createElement("option", {
      value: "tech"
    }, "\u6280\u672F/\u7814\u53D1"), /*#__PURE__*/React.createElement("option", {
      value: "product"
    }, "\u4EA7\u54C1"), /*#__PURE__*/React.createElement("option", {
      value: "operation"
    }, "\u8FD0\u8425"), /*#__PURE__*/React.createElement("option", {
      value: "market"
    }, "\u5E02\u573A/BD"), /*#__PURE__*/React.createElement("option", {
      value: "design"
    }, "\u8BBE\u8BA1"), /*#__PURE__*/React.createElement("option", {
      value: "data"
    }, "\u6570\u636E/\u5206\u6790"), /*#__PURE__*/React.createElement("option", {
      value: "other"
    }, "\u5176\u4ED6")), /*#__PURE__*/React.createElement("div", {
      className: "grid grid-cols-2 gap-2.5"
    }, /*#__PURE__*/React.createElement("input", {
      className: "px-3 py-2.5 rounded-lg border border-gray-200 text-sm",
      placeholder: "\u5B66\u6821\uFF08\u9009\u586B\uFF09",
      value: form.school,
      onChange: e => setForm({
        ...form,
        school: e.target.value
      })
    }), /*#__PURE__*/React.createElement("input", {
      type: "number",
      min: "2020",
      max: "2035",
      className: "px-3 py-2.5 rounded-lg border border-gray-200 text-sm",
      placeholder: "\u6BD5\u4E1A\u5E74\u4EFD\uFF08\u9009\u586B\uFF09",
      value: form.graduation_year,
      onChange: e => setForm({
        ...form,
        graduation_year: e.target.value
      })
    })), /*#__PURE__*/React.createElement("button", {
      onClick: submit,
      disabled: submitting,
      className: "w-full py-2.5 rounded-lg bg-white border border-gray-300 text-sm text-gray-700 hover:bg-gray-50 btn-apple disabled:opacity-50"
    }, submitting ? '保存中...' : '填写信息并开始')))
  }];
  const current = cards[step];
  return /*#__PURE__*/React.createElement("div", {
    className: 'modal-overlay transition-opacity duration-300 ' + (leaving ? 'opacity-0' : ''),
    style: leaving ? {
      animation: 'none'
    } : {}
  }, /*#__PURE__*/React.createElement("div", {
    className: 'modal-card max-w-md p-5 sm:p-6 transition-all duration-300 relative ' + (leaving ? 'opacity-0 scale-95' : ''),
    style: leaving ? {
      animation: 'none'
    } : {}
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex gap-1.5 mb-5 pr-10"
  }, cards.map((_, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    className: 'h-1 rounded-full flex-1 transition-all duration-400 ' + (i <= step ? 'bg-brand-600' : 'bg-gray-200')
  }))), step < cards.length - 1 && /*#__PURE__*/React.createElement("button", {
    onClick: skip,
    className: "absolute top-5 right-5 text-[11px] text-gray-400 hover:text-gray-600 transition"
  }, "\u8DF3\u8FC7 \u2192"), /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-3 mb-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "w-9 h-9 rounded-xl bg-gradient-to-br from-brand-50 to-brand-100 flex items-center justify-center text-lg"
  }, current.icon), /*#__PURE__*/React.createElement("h2", {
    className: "text-lg font-semibold text-gray-900"
  }, current.title)), /*#__PURE__*/React.createElement("div", {
    className: "mb-6"
  }, current.body), step < cards.length - 1 && /*#__PURE__*/React.createElement("div", {
    className: "flex gap-3"
  }, step > 0 && /*#__PURE__*/React.createElement("button", {
    onClick: () => setStep(step - 1),
    className: "px-4 py-2 rounded-lg border border-gray-300 text-sm font-medium text-gray-700 hover:bg-gray-50 btn-apple"
  }, "\u4E0A\u4E00\u6B65"), /*#__PURE__*/React.createElement("div", {
    className: "flex-1"
  }), /*#__PURE__*/React.createElement("button", {
    onClick: () => setStep(step + 1),
    className: "px-5 py-2 rounded-lg bg-brand-600 text-white text-sm font-medium hover:bg-brand-700 btn-apple"
  }, "\u7EE7\u7EED ", /*#__PURE__*/React.createElement(Icon.ArrowRight, {
    className: "inline w-4 h-4 ml-1"
  })))));
}

// ==================== 页面：Home / Dashboard ====================
function HomePage() {
  const {
    user,
    navigate
  } = useApp();
  const [stats, setStats] = useState(null);
  const [quota, setQuota] = useState(null);
  const [positions, setPositions] = useState([]);
  const [suggestions, setSuggestions] = useState([]);
  const [recentReviews, setRecentReviews] = useState([]);
  useEffect(() => {
    (async () => {
      try {
        const [q, pos, sug, rv] = await Promise.all([apiCall('/api/me/quota'), apiCall('/api/positions'), apiCall('/api/suggestions?new=1'), apiCall('/api/reviews')]);
        setQuota(q);
        setPositions(pos.positions || []);
        setSuggestions(sug.suggestions || []);
        setRecentReviews(rv.reviews || []);
      } catch {}
    })();
  }, []);

  // 岗位按状态分组
  const positionsByStatus = useMemo(() => {
    const groups = {
      active: [],
      // 投递中、笔试、面试
      won: [],
      // offer、入职
      closed: [] // 拒绝、放弃
    };
    for (const p of positions) {
      if (['offer', 'onboard'].includes(p.status)) groups.won.push(p);else if (['rejected', 'withdrawn'].includes(p.status)) groups.closed.push(p);else groups.active.push(p);
    }
    return groups;
  }, [positions]);
  const hello = (() => {
    const h = new Date().getHours();
    if (h < 6) return '深夜好';
    if (h < 12) return '早上好';
    if (h < 18) return '下午好';
    return '晚上好';
  })();
  return /*#__PURE__*/React.createElement("div", {
    className: "space-y-6 animate-page-enter"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex flex-col md:flex-row md:items-end md:justify-between gap-4"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h1", {
    className: "text-2xl md:text-3xl font-semibold text-gray-900"
  }, hello, "\uFF0C", user?.name || '你', " \uD83D\uDC4B"), /*#__PURE__*/React.createElement("p", {
    className: "text-sm text-gray-600 mt-1"
  }, "AI \u968F\u4F60\u4F7F\u7528\u8D8A\u6DF1\u5165\uFF0C\u8D8A\u80FD\u7ED9\u51FA\u7CBE\u51C6\u5EFA\u8BAE\u3002")), quota && /*#__PURE__*/React.createElement("div", {
    className: "bg-white rounded-xl border border-gray-200 shadow-soft px-4 py-3 flex gap-5 text-sm"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-500"
  }, "\u4ECA\u65E5\u5FEB\u901F AI"), /*#__PURE__*/React.createElement("div", {
    className: "font-semibold text-gray-900 animate-count"
  }, quota.flash.used, " / ", quota.flash.limit)), /*#__PURE__*/React.createElement("div", {
    className: "w-px bg-gray-200"
  }), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-500"
  }, "\u4ECA\u65E5\u6DF1\u5EA6 AI"), /*#__PURE__*/React.createElement("div", {
    className: "font-semibold text-gray-900 animate-count"
  }, quota.pro.used, " / ", quota.pro.limit)))), positions.length === 0 && recentReviews.length === 0 && /*#__PURE__*/React.createElement("div", {
    className: "bg-gradient-to-br from-brand-50 to-accent-50 rounded-2xl p-6 md:p-8 border border-brand-100"
  }, /*#__PURE__*/React.createElement("h2", {
    className: "text-lg font-semibold text-gray-900 mb-1"
  }, "\u4ECE\u8FD9\u4E09\u6B65\u5F00\u59CB"), /*#__PURE__*/React.createElement("p", {
    className: "text-sm text-gray-600 mb-5"
  }, "\u7C98\u8D34\u4E00\u6B21\uFF0CAI \u5F00\u59CB\u5DE5\u4F5C\u3002"), /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-1 md:grid-cols-3 gap-3"
  }, /*#__PURE__*/React.createElement(QuickAction, {
    num: "1",
    title: "\u7C98\u8D34\u4E3B\u7B80\u5386",
    desc: "\u8BA9 AI \u4E86\u89E3\u4F60\u7684\u80CC\u666F\u548C\u80FD\u529B",
    onClick: () => navigate('resumes')
  }), /*#__PURE__*/React.createElement(QuickAction, {
    num: "2",
    title: "\u7C98\u8D34\u76EE\u6807 JD",
    desc: "\u81EA\u52A8\u7ED9\u51FA\u5339\u914D\u5206\u6790\u548C\u8272\u5757\u63D0\u793A",
    onClick: () => navigate('jds')
  }), /*#__PURE__*/React.createElement(QuickAction, {
    num: "3",
    title: "\u8BB0\u5F55\u9762\u8BD5\u548C\u590D\u76D8",
    desc: "AI \u8DE8\u6B21\u8FFD\u8E2A\u6210\u957F\u8F68\u8FF9",
    onClick: () => navigate('positions')
  }))), positions.length > 0 && /*#__PURE__*/React.createElement("section", null, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center justify-between mb-3"
  }, /*#__PURE__*/React.createElement("h2", {
    className: "text-lg font-semibold text-gray-900"
  }, "\u5C97\u4F4D\u770B\u677F"), /*#__PURE__*/React.createElement("button", {
    onClick: () => navigate('positions'),
    className: "text-sm text-brand-600 hover:text-brand-700 font-medium btn-apple"
  }, "\u67E5\u770B\u5168\u90E8 \u2192")), /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-1 md:grid-cols-3 gap-3"
  }, /*#__PURE__*/React.createElement(LaneCard, {
    label: "\u8FDB\u884C\u4E2D",
    count: positionsByStatus.active.length,
    color: "brand",
    items: positionsByStatus.active.slice(0, 3)
  }), /*#__PURE__*/React.createElement(LaneCard, {
    label: "Offer/\u5165\u804C",
    count: positionsByStatus.won.length,
    color: "accent",
    items: positionsByStatus.won.slice(0, 3)
  }), /*#__PURE__*/React.createElement(LaneCard, {
    label: "\u5DF2\u7ED3\u675F",
    count: positionsByStatus.closed.length,
    color: "gray",
    items: positionsByStatus.closed.slice(0, 3)
  }))), suggestions.length > 0 && /*#__PURE__*/React.createElement("section", null, /*#__PURE__*/React.createElement("h2", {
    className: "text-lg font-semibold text-gray-900 mb-3"
  }, "\uD83D\uDCA1 AI \u5EFA\u8BAE \xB7 ", suggestions.length, " \u6761\u5F85\u67E5\u770B"), /*#__PURE__*/React.createElement("div", {
    className: "space-y-2"
  }, suggestions.slice(0, 2).map(s => /*#__PURE__*/React.createElement("div", {
    key: s.id,
    onClick: () => navigate('suggestions'),
    className: "card-apple clickable bg-white border border-gray-200 rounded-xl p-4 shadow-soft hover:shadow-lifted cursor-pointer"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-sm font-medium text-gray-900"
  }, s.title), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-600 mt-1 line-clamp-2"
  }, s.content))))), recentReviews.length > 0 && /*#__PURE__*/React.createElement("section", null, /*#__PURE__*/React.createElement("h2", {
    className: "text-lg font-semibold text-gray-900 mb-3"
  }, "\uD83D\uDCDD \u6700\u8FD1\u590D\u76D8"), /*#__PURE__*/React.createElement("div", {
    className: "space-y-2"
  }, recentReviews.slice(0, 3).map(r => /*#__PURE__*/React.createElement("div", {
    key: r.id,
    className: "card-apple bg-white border border-gray-200 rounded-xl p-4 shadow-soft"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-sm font-medium text-gray-900"
  }, r.company || '未关联岗位', " \xB7 ", r.position_title || ''), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-500 mt-0.5"
  }, new Date(r.created_at).toLocaleString('zh-CN')), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-600 mt-2 line-clamp-2"
  }, r.preview))))));
}
function QuickAction({
  num,
  title,
  desc,
  onClick
}) {
  return /*#__PURE__*/React.createElement("button", {
    onClick: onClick,
    className: "card-apple clickable text-left bg-white border border-gray-200 rounded-xl p-4 shadow-soft hover:shadow-lifted btn-apple"
  }, /*#__PURE__*/React.createElement("div", {
    className: "w-7 h-7 rounded-full bg-brand-600 text-white text-sm font-semibold flex items-center justify-center mb-2"
  }, num), /*#__PURE__*/React.createElement("div", {
    className: "text-sm font-semibold text-gray-900"
  }, title), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-600 mt-1 leading-relaxed"
  }, desc));
}
function LaneCard({
  label,
  count,
  color,
  items
}) {
  const {
    navigate
  } = useApp();
  const colorMap = {
    brand: 'bg-brand-50 text-brand-700 border-brand-200',
    accent: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    gray: 'bg-gray-50 text-gray-600 border-gray-200'
  };
  return /*#__PURE__*/React.createElement("div", {
    className: "bg-white rounded-xl border border-gray-200 p-4 shadow-soft"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center justify-between mb-3"
  }, /*#__PURE__*/React.createElement("span", {
    className: 'inline-flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-semibold border ' + colorMap[color]
  }, label, " ", /*#__PURE__*/React.createElement("span", {
    className: "opacity-70"
  }, count))), items.length === 0 ? /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-400 py-3 text-center"
  }, "\u6682\u65E0") : /*#__PURE__*/React.createElement("div", {
    className: "space-y-1.5"
  }, items.map(p => /*#__PURE__*/React.createElement("button", {
    key: p.id,
    onClick: () => navigate('positions/' + p.id),
    className: "w-full text-left px-2 py-1.5 rounded-md text-sm text-gray-700 hover:bg-gray-50 transition"
  }, /*#__PURE__*/React.createElement("div", {
    className: "font-medium truncate"
  }, p.company), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-500 truncate"
  }, p.position_title)))));
}

// ==================== 通用组件 ====================

function Card({
  children,
  className = '',
  onClick,
  clickable
}) {
  return /*#__PURE__*/React.createElement("div", {
    onClick: onClick,
    className: 'card-apple ' + (clickable ? 'clickable cursor-pointer ' : '') + 'bg-white rounded-xl border border-gray-200 shadow-soft ' + className
  }, children);
}
function Button({
  children,
  onClick,
  variant = 'primary',
  size = 'md',
  disabled,
  className = '',
  type = 'button'
}) {
  const base = 'btn-apple inline-flex items-center justify-center font-medium rounded-lg transition disabled:opacity-50 disabled:cursor-not-allowed ';
  const sizes = {
    sm: 'px-3 py-1.5 text-xs',
    md: 'px-4 py-2 text-sm',
    lg: 'px-5 py-2.5 text-sm'
  };
  const variants = {
    primary: 'bg-brand-600 text-white hover:bg-brand-700 shadow-soft',
    secondary: 'bg-white border border-gray-300 text-gray-800 hover:bg-gray-50',
    ghost: 'text-gray-700 hover:bg-gray-100',
    danger: 'bg-rose-600 text-white hover:bg-rose-700',
    accent: 'bg-accent-500 text-white hover:bg-accent-600'
  };
  return /*#__PURE__*/React.createElement("button", {
    type: type,
    onClick: onClick,
    disabled: disabled,
    className: base + sizes[size] + ' ' + variants[variant] + ' ' + className
  }, children);
}
function EmptyState({
  icon = '📄',
  title,
  desc,
  action
}) {
  return /*#__PURE__*/React.createElement("div", {
    className: "text-center py-12 px-4"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-5xl mb-3 opacity-40"
  }, icon), /*#__PURE__*/React.createElement("div", {
    className: "text-sm font-semibold text-gray-800"
  }, title), desc && /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-500 mt-1 max-w-sm mx-auto"
  }, desc), action && /*#__PURE__*/React.createElement("div", {
    className: "mt-4"
  }, action));
}
function Modal({
  open,
  onClose,
  title,
  children,
  maxWidth = 'max-w-lg'
}) {
  useEffect(() => {
    if (!open) return;
    const handler = e => e.key === 'Escape' && onClose();
    document.addEventListener('keydown', handler);
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', handler);
      document.body.style.overflow = '';
    };
  }, [open, onClose]);
  if (!open) return null;
  return ReactDOM.createPortal(/*#__PURE__*/React.createElement("div", {
    className: "modal-overlay",
    onClick: onClose
  }, /*#__PURE__*/React.createElement("div", {
    className: 'modal-card ' + maxWidth,
    onClick: e => e.stopPropagation()
  }, title && /*#__PURE__*/React.createElement("div", {
    className: "modal-header"
  }, /*#__PURE__*/React.createElement("h3", null, title), /*#__PURE__*/React.createElement("button", {
    onClick: onClose,
    className: "w-8 h-8 rounded-full flex items-center justify-center text-gray-400 hover:text-gray-700 hover:bg-gray-100 transition -mr-1"
  }, /*#__PURE__*/React.createElement("svg", {
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round",
    strokeLinejoin: "round",
    className: "w-[18px] h-[18px]"
  }, /*#__PURE__*/React.createElement("line", {
    x1: "18",
    y1: "6",
    x2: "6",
    y2: "18"
  }), /*#__PURE__*/React.createElement("line", {
    x1: "6",
    y1: "6",
    x2: "18",
    y2: "18"
  })))), /*#__PURE__*/React.createElement("div", {
    className: "modal-body"
  }, children))), document.body);
}
function PageHeader({
  title,
  desc,
  action
}) {
  return /*#__PURE__*/React.createElement("div", {
    className: "flex flex-col md:flex-row md:items-end md:justify-between gap-4 mb-6"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h1", {
    className: "text-2xl md:text-3xl font-semibold text-gray-900"
  }, title), desc && /*#__PURE__*/React.createElement("p", {
    className: "text-sm text-gray-600 mt-1"
  }, desc)), action);
}

// 6 档色块
const BAND_CONFIG = {
  excellent: {
    color: 'bg-emerald-600',
    label: '极高匹配',
    text: 'text-emerald-700'
  },
  great: {
    color: 'bg-emerald-500',
    label: '高匹配',
    text: 'text-emerald-600'
  },
  good: {
    color: 'bg-emerald-300',
    label: '中高匹配',
    text: 'text-emerald-600'
  },
  fair: {
    color: 'bg-amber-200',
    label: '中等',
    text: 'text-amber-700'
  },
  low: {
    color: 'bg-slate-300',
    label: '偏低',
    text: 'text-slate-600'
  },
  poor: {
    color: 'bg-slate-200',
    label: '不匹配',
    text: 'text-slate-500'
  },
  unknown: {
    color: 'bg-gray-100',
    label: '未评估',
    text: 'text-gray-400'
  }
};
function MatchBand({
  score,
  band,
  size = 'sm',
  showLabel = false,
  showScore = false
}) {
  const cfg = BAND_CONFIG[band] || BAND_CONFIG.unknown;
  const w = size === 'sm' ? 'w-1' : size === 'md' ? 'w-1.5' : 'w-2';
  const h = size === 'sm' ? 'h-6' : size === 'md' ? 'h-8' : 'h-10';
  return /*#__PURE__*/React.createElement("div", {
    className: "inline-flex items-center gap-2",
    title: cfg.label + (score != null ? ' · ' + score : '')
  }, /*#__PURE__*/React.createElement("span", {
    className: 'rounded-full ' + cfg.color + ' ' + w + ' ' + h
  }), showScore && score != null && /*#__PURE__*/React.createElement("span", {
    className: "text-sm font-semibold text-gray-800"
  }, score), showLabel && /*#__PURE__*/React.createElement("span", {
    className: 'text-xs font-medium ' + cfg.text
  }, cfg.label));
}

// 分数转 band（前端本地计算，和后端 scoreToBand 保持一致）
function scoreToBand(score) {
  if (score == null) return 'unknown';
  if (score >= 88) return 'excellent';
  if (score >= 78) return 'great';
  if (score >= 68) return 'good';
  if (score >= 55) return 'fair';
  if (score >= 40) return 'low';
  return 'poor';
}
const STATUS_LABELS = {
  pending: '待投递',
  applied: '已投递',
  written_test: '笔试中',
  interview_1: '一面',
  interview_2: '二面',
  interview_3plus: '三面+',
  offer: 'Offer',
  onboard: '已入职',
  rejected: '已拒绝',
  withdrawn: '主动放弃'
};
const STATUS_COLORS = {
  pending: 'bg-gray-100 text-gray-700 border-gray-200',
  applied: 'bg-brand-50 text-brand-700 border-brand-200',
  written_test: 'bg-indigo-50 text-indigo-700 border-indigo-200',
  interview_1: 'bg-purple-50 text-purple-700 border-purple-200',
  interview_2: 'bg-purple-50 text-purple-700 border-purple-200',
  interview_3plus: 'bg-purple-50 text-purple-700 border-purple-200',
  offer: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  onboard: 'bg-emerald-100 text-emerald-800 border-emerald-300',
  rejected: 'bg-slate-100 text-slate-600 border-slate-200',
  withdrawn: 'bg-slate-100 text-slate-500 border-slate-200'
};
function StatusBadge({
  status
}) {
  const color = STATUS_COLORS[status] || STATUS_COLORS.pending;
  return /*#__PURE__*/React.createElement("span", {
    className: 'inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium border ' + color
  }, STATUS_LABELS[status] || status);
}
function relTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  const diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 60) return '刚刚';
  if (diff < 3600) return Math.floor(diff / 60) + ' 分钟前';
  if (diff < 86400) return Math.floor(diff / 3600) + ' 小时前';
  if (diff < 86400 * 30) return Math.floor(diff / 86400) + ' 天前';
  return d.toLocaleDateString('zh-CN');
}
function handleApiError(err, toast, onQuotaExceeded) {
  if (err.status === 429 && err.data?.error === 'quota_exceeded') {
    if (onQuotaExceeded) onQuotaExceeded(err.data);else toast(err.data.message || '今日 AI 额度已用完', 'error', 5000);
    return;
  }
  toast(err.message || '操作失败', 'error');
}
function Section({
  title,
  children
}) {
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2"
  }, title), children);
}

// ==================== 页面：简历管理 ====================
function ResumesPage() {
  const {
    toast
  } = useApp();
  const [list, setList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [editor, setEditor] = useState(null);
  const [viewing, setViewing] = useState(null);
  const load = async () => {
    setLoading(true);
    try {
      const r = await apiCall('/api/resumes');
      setList(r.resumes || []);
    } catch (e) {
      toast(e.message, 'error');
    }
    setLoading(false);
  };
  useEffect(() => {
    load();
  }, []);
  const del = async id => {
    if (!confirm('确定删除这份简历？')) return;
    try {
      await apiCall('/api/resumes/' + id, {
        method: 'DELETE'
      });
      toast('已删除', 'success');
      load();
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  const setPrimary = async id => {
    try {
      await apiCall('/api/resumes/' + id, {
        method: 'PUT',
        body: JSON.stringify({
          is_primary: true
        })
      });
      toast('已设为主简历', 'success');
      load();
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  return /*#__PURE__*/React.createElement("div", {
    className: "animate-slide-up"
  }, /*#__PURE__*/React.createElement(PageHeader, {
    title: "\u7B80\u5386\u7BA1\u7406",
    desc: "最多 " + list.length + "/5 份 · 粘贴文本，AI 自动结构化解析",
    action: /*#__PURE__*/React.createElement(Button, {
      variant: "primary",
      onClick: () => setEditor({
        mode: 'new'
      }),
      disabled: list.length >= 5
    }, /*#__PURE__*/React.createElement(Icon.Plus, {
      className: "w-4 h-4 mr-1"
    }), " \u7C98\u8D34\u65B0\u7B80\u5386")
  }), loading ? /*#__PURE__*/React.createElement(Card, {
    className: "p-8 text-center text-gray-400 text-sm"
  }, "\u52A0\u8F7D\u4E2D...") : list.length === 0 ? /*#__PURE__*/React.createElement(Card, {
    className: "p-0"
  }, /*#__PURE__*/React.createElement(EmptyState, {
    icon: "\uD83D\uDCC4",
    title: "\u8FD8\u6CA1\u6709\u7B80\u5386",
    desc: "\u7C98\u8D34\u4F60\u7684\u7B80\u5386\u6587\u672C\uFF0CAI \u4F1A\u81EA\u52A8\u63D0\u53D6\u7ED3\u6784\u5316\u4FE1\u606F",
    action: /*#__PURE__*/React.createElement(Button, {
      variant: "primary",
      onClick: () => setEditor({
        mode: 'new'
      })
    }, "\u7C98\u8D34\u7B2C\u4E00\u4EFD\u7B80\u5386")
  })) : /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-1 md:grid-cols-2 gap-3"
  }, list.map(r => /*#__PURE__*/React.createElement(Card, {
    key: r.id,
    className: "p-4"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-2 mb-2 flex-wrap"
  }, /*#__PURE__*/React.createElement("span", {
    className: "font-semibold text-gray-900 truncate"
  }, r.title), r.is_primary === 1 && /*#__PURE__*/React.createElement("span", {
    className: "px-1.5 py-0.5 text-[10px] rounded bg-brand-50 text-brand-700 font-semibold border border-brand-200"
  }, "\u4E3B\u7B80\u5386"), r.parse_status === 'processing' && /*#__PURE__*/React.createElement("span", {
    className: "text-[10px] text-gray-400"
  }, "\u89E3\u6790\u4E2D..."), r.parse_status === 'failed' && /*#__PURE__*/React.createElement("span", {
    className: "text-[10px] text-rose-500"
  }, "\u89E3\u6790\u5931\u8D25")), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-500 mb-2"
  }, relTime(r.updated_at)), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-600 line-clamp-3 leading-relaxed mb-3 min-h-[3rem]"
  }, r.preview), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-1 flex-wrap"
  }, /*#__PURE__*/React.createElement(Button, {
    size: "sm",
    variant: "ghost",
    onClick: () => setViewing(r)
  }, "\u67E5\u770B"), /*#__PURE__*/React.createElement(Button, {
    size: "sm",
    variant: "ghost",
    onClick: () => setEditor({
      mode: 'edit',
      data: r
    })
  }, "\u7F16\u8F91"), r.is_primary !== 1 && /*#__PURE__*/React.createElement(Button, {
    size: "sm",
    variant: "ghost",
    onClick: () => setPrimary(r.id)
  }, "\u8BBE\u4E3B"), /*#__PURE__*/React.createElement("div", {
    className: "flex-1"
  }), /*#__PURE__*/React.createElement(Button, {
    size: "sm",
    variant: "ghost",
    onClick: () => del(r.id),
    className: "text-rose-600 hover:bg-rose-50"
  }, "\u5220\u9664"))))), editor && /*#__PURE__*/React.createElement(ResumeEditor, {
    mode: editor.mode,
    data: editor.data,
    onClose: () => setEditor(null),
    onSaved: () => {
      setEditor(null);
      load();
    }
  }), viewing && /*#__PURE__*/React.createElement(ResumeViewer, {
    resumeId: viewing.id,
    onClose: () => setViewing(null)
  }));
}
function ResumeEditor({
  mode,
  data,
  onClose,
  onSaved
}) {
  const {
    toast
  } = useApp();
  const [title, setTitle] = useState(data?.title || '');
  const [rawText, setRawText] = useState('');
  const [isPrimary, setIsPrimary] = useState(data?.is_primary === 1);
  const [submitting, setSubmitting] = useState(false);
  useEffect(() => {
    if (mode === 'edit' && data?.id) {
      apiCall('/api/resumes/' + data.id).then(r => setRawText(r.resume.raw_text || '')).catch(() => {});
    }
  }, [mode, data?.id]);
  const submit = async () => {
    if (rawText.trim().length < 20) return toast('简历太短', 'error');
    setSubmitting(true);
    try {
      if (mode === 'new') {
        const r = await apiCall('/api/resumes', {
          method: 'POST',
          body: JSON.stringify({
            title: title.trim() || '未命名简历',
            raw_text: rawText,
            is_primary: isPrimary
          })
        });
        if (r.error) {
          toast(r.error || '解析失败', 'error');
        } else {
          toast('保存并解析完成', 'success');
        }
        onSaved();
      } else {
        const payload = {
          title: title.trim(),
          raw_text: rawText
        };
        if (isPrimary) payload.is_primary = true;
        await apiCall('/api/resumes/' + data.id, {
          method: 'PUT',
          body: JSON.stringify(payload)
        });
        toast('已更新', 'success');
        onSaved();
      }
    } catch (e) {
      handleApiError(e, toast);
    }
    setSubmitting(false);
  };
  return /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: onClose,
    title: mode === 'new' ? '粘贴新简历' : '编辑简历',
    maxWidth: "max-w-2xl"
  }, /*#__PURE__*/React.createElement("div", {
    className: "space-y-3"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u7B80\u5386\u6807\u9898"), /*#__PURE__*/React.createElement("input", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm",
    placeholder: "\u5982\uFF1A\u4EA7\u54C1\u5C97\u4E3B\u7B80\u5386",
    value: title,
    onChange: e => setTitle(e.target.value)
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u7B80\u5386\u5185\u5BB9\uFF08\u7C98\u8D34\u7EAF\u6587\u672C\uFF09"), /*#__PURE__*/React.createElement("textarea", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm leading-relaxed",
    rows: 8,
    placeholder: "\u7C98\u8D34\u5B8C\u6574\u7B80\u5386\u6587\u672C\uFF0CAI \u4F1A\u81EA\u52A8\u8BC6\u522B\u5E76\u7ED3\u6784\u5316...",
    value: rawText,
    onChange: e => setRawText(e.target.value)
  }), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-400 mt-1"
  }, rawText.length, " \u5B57")), /*#__PURE__*/React.createElement("label", {
    className: "flex items-center gap-2 text-sm text-gray-700 cursor-pointer"
  }, /*#__PURE__*/React.createElement("input", {
    type: "checkbox",
    checked: isPrimary,
    onChange: e => setIsPrimary(e.target.checked),
    className: "w-4 h-4 rounded accent-brand-600"
  }), "\u8BBE\u4E3A\u4E3B\u7B80\u5386\uFF08\u7528\u4E8E JD \u5339\u914D\u9ED8\u8BA4\u7B80\u5386\uFF09"), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 justify-end"
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "secondary",
    onClick: onClose
  }, "\u53D6\u6D88"), /*#__PURE__*/React.createElement(Button, {
    variant: "primary",
    onClick: submit,
    disabled: submitting
  }, submitting ? mode === 'new' ? 'AI 解析中...' : '保存中...' : mode === 'new' ? '保存并解析' : '保存'))));
}
function ResumeViewer({
  resumeId,
  onClose
}) {
  const [resume, setResume] = useState(null);
  const [error, setError] = useState(false);
  useEffect(() => {
    apiCall('/api/resumes/' + resumeId).then(r => setResume(r.resume)).catch(() => setError(true));
  }, [resumeId]);
  const p = resume?.parsed;
  return /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: onClose,
    title: resume?.title || '简历详情',
    maxWidth: "max-w-2xl"
  }, error ? /*#__PURE__*/React.createElement("div", {
    className: "text-sm text-red-500 py-4 text-center"
  }, "\u52A0\u8F7D\u5931\u8D25\uFF0C\u8BF7\u91CD\u8BD5") : !resume ? /*#__PURE__*/React.createElement("div", {
    className: "text-sm text-gray-400 py-4 text-center"
  }, "\u52A0\u8F7D\u4E2D...") : !p ? /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-500 mb-2"
  }, "AI \u89E3\u6790\u7ED3\u679C\u6682\u65E0\uFF0C\u663E\u793A\u539F\u6587\uFF1A"), /*#__PURE__*/React.createElement("pre", {
    className: "text-xs bg-gray-50 rounded p-3 whitespace-pre-wrap leading-relaxed"
  }, resume.raw_text)) : /*#__PURE__*/React.createElement("div", {
    className: "space-y-5 text-sm"
  }, p.basic && /*#__PURE__*/React.createElement(Section, {
    title: "\u57FA\u7840\u4FE1\u606F"
  }, /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-2 gap-2 text-xs text-gray-700"
  }, p.basic.name && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("span", {
    className: "text-gray-400"
  }, "\u59D3\u540D\uFF1A"), p.basic.name), p.basic.email && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("span", {
    className: "text-gray-400"
  }, "\u90AE\u7BB1\uFF1A"), p.basic.email), p.basic.phone && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("span", {
    className: "text-gray-400"
  }, "\u7535\u8BDD\uFF1A"), p.basic.phone), p.basic.city && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("span", {
    className: "text-gray-400"
  }, "\u57CE\u5E02\uFF1A"), p.basic.city))), p.education?.length > 0 && /*#__PURE__*/React.createElement(Section, {
    title: "\u6559\u80B2\u7ECF\u5386"
  }, p.education.map((e, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    className: "mb-2 text-xs"
  }, /*#__PURE__*/React.createElement("div", {
    className: "font-medium text-gray-900"
  }, e.school, " \xB7 ", e.major, " \xB7 ", e.degree), /*#__PURE__*/React.createElement("div", {
    className: "text-gray-500"
  }, e.period, e.gpa ? ' · ' + e.gpa : '')))), p.experiences?.length > 0 && /*#__PURE__*/React.createElement(Section, {
    title: "\u5DE5\u4F5C/\u5B9E\u4E60"
  }, p.experiences.map((e, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    className: "mb-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "font-medium text-sm text-gray-900"
  }, e.company, " \xB7 ", e.role), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-500 mb-1"
  }, e.period), e.description && /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-700 mb-1"
  }, e.description), e.achievements?.length > 0 && /*#__PURE__*/React.createElement("ul", {
    className: "text-xs text-gray-600 ml-4 list-disc"
  }, e.achievements.map((a, j) => /*#__PURE__*/React.createElement("li", {
    key: j
  }, a)))))), p.projects?.length > 0 && /*#__PURE__*/React.createElement(Section, {
    title: "\u9879\u76EE"
  }, p.projects.map((e, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    className: "mb-2"
  }, /*#__PURE__*/React.createElement("div", {
    className: "font-medium text-sm text-gray-900"
  }, e.name, e.role ? ' · ' + e.role : ''), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-500"
  }, e.period), e.description && /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-700 mt-0.5"
  }, e.description), e.tech_stack?.length > 0 && /*#__PURE__*/React.createElement("div", {
    className: "mt-1 flex gap-1 flex-wrap"
  }, e.tech_stack.map((t, j) => /*#__PURE__*/React.createElement("span", {
    key: j,
    className: "px-1.5 py-0.5 rounded bg-brand-50 text-brand-700 text-[10px]"
  }, t)))))), p.skills?.length > 0 && /*#__PURE__*/React.createElement(Section, {
    title: "\u6280\u80FD"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex gap-1.5 flex-wrap"
  }, p.skills.map((s, i) => /*#__PURE__*/React.createElement("span", {
    key: i,
    className: "px-2 py-0.5 rounded bg-gray-100 text-gray-700 text-xs"
  }, s)))), p.awards?.length > 0 && /*#__PURE__*/React.createElement(Section, {
    title: "\u83B7\u5956/\u8BC1\u4E66"
  }, /*#__PURE__*/React.createElement("ul", {
    className: "text-xs text-gray-700 ml-4 list-disc"
  }, p.awards.map((a, i) => /*#__PURE__*/React.createElement("li", {
    key: i
  }, a))))));
}

// ==================== 页面：JD 库 ====================
function JDsPage() {
  const {
    toast,
    navigate
  } = useApp();
  const [list, setList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [q, setQ] = useState('');
  const [editor, setEditor] = useState(null);
  const [bindingJd, setBindingJd] = useState(null);
  const load = async query => {
    try {
      const r = await apiCall('/api/jds' + (query ? '?q=' + encodeURIComponent(query) : ''));
      setList(r.jds || []);
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  useEffect(() => {
    load('').finally(() => setLoading(false));
  }, []);
  useEffect(() => {
    const t = setTimeout(() => load(q), 300);
    return () => clearTimeout(t);
  }, [q]);

  // 轮询：如果列表中有 processing 状态的 JD，每 3 秒重新拉取
  useEffect(() => {
    const hasProcessing = list.some(j => j.parse_status === 'processing');
    if (!hasProcessing) return;
    const timer = setInterval(() => load(q), 3000);
    return () => clearInterval(timer);
  }, [list, q]);
  const del = async (id, e) => {
    e.stopPropagation();
    if (!confirm('确定删除这个 JD？')) return;
    try {
      await apiCall('/api/jds/' + id, {
        method: 'DELETE'
      });
      toast('已删除', 'success');
      load(q);
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  const runDeepMatch = async (id, e) => {
    e.stopPropagation();
    toast('正在生成深度分析...', 'info');
    try {
      await apiCall('/api/jds/' + id + '/match', {
        method: 'POST',
        body: JSON.stringify({})
      });
      toast('深度分析完成', 'success');
      load(q);
    } catch (e) {
      handleApiError(e, toast);
    }
  };
  return /*#__PURE__*/React.createElement("div", {
    className: "animate-slide-up"
  }, /*#__PURE__*/React.createElement(PageHeader, {
    title: "JD \u5E93",
    desc: "\u7C98\u8D34\u5C97\u4F4D JD \xB7 \u81EA\u52A8\u8272\u5757\u8BC4\u4F30 \xB7 \u652F\u6301\u6DF1\u5EA6\u5339\u914D\u5206\u6790",
    action: /*#__PURE__*/React.createElement(Button, {
      variant: "primary",
      onClick: () => setEditor({})
    }, /*#__PURE__*/React.createElement(Icon.Plus, {
      className: "w-4 h-4 mr-1"
    }), " \u7C98\u8D34\u65B0 JD")
  }), /*#__PURE__*/React.createElement("div", {
    className: "mb-4"
  }, /*#__PURE__*/React.createElement("input", {
    className: "w-full max-w-sm px-3 py-2 rounded-lg border border-gray-300 text-sm bg-white",
    placeholder: "\u641C\u7D22\u516C\u53F8/\u5C97\u4F4D\u540D...",
    value: q,
    onChange: e => setQ(e.target.value)
  })), loading ? /*#__PURE__*/React.createElement(Card, {
    className: "p-8 text-center text-gray-400 text-sm"
  }, "\u52A0\u8F7D\u4E2D...") : list.length === 0 ? /*#__PURE__*/React.createElement(Card, {
    className: "p-0"
  }, /*#__PURE__*/React.createElement(EmptyState, {
    icon: "\uD83D\uDCBC",
    title: q ? '没有匹配的 JD' : '还没有 JD',
    desc: q ? '试试别的关键词' : '粘贴 JD 文本，AI 会在后台自动解析并评估匹配度',
    action: !q && /*#__PURE__*/React.createElement(Button, {
      variant: "primary",
      onClick: () => setEditor({})
    }, "\u7C98\u8D34\u7B2C\u4E00\u4E2A JD")
  })) : /*#__PURE__*/React.createElement("div", {
    className: "space-y-2"
  }, list.map(j => {
    const quick = j.match_quick ? typeof j.match_quick === 'string' ? JSON.parse(j.match_quick) : j.match_quick : null;
    const processing = j.parse_status === 'processing';
    const failed = j.parse_status === 'failed';
    return /*#__PURE__*/React.createElement(Card, {
      key: j.id,
      clickable: !processing,
      onClick: () => !processing && navigate('jds/' + j.id),
      className: "p-4"
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex items-center gap-3"
    }, processing ? /*#__PURE__*/React.createElement("div", {
      className: "w-1.5 h-8 rounded-full bg-gradient-to-b from-brand-400 to-brand-600 animate-pulse"
    }) : /*#__PURE__*/React.createElement(MatchBand, {
      score: j.match_score,
      band: quick?.band || 'unknown',
      size: "md"
    }), /*#__PURE__*/React.createElement("div", {
      className: "flex-1 min-w-0"
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex items-center gap-2 flex-wrap"
    }, /*#__PURE__*/React.createElement("span", {
      className: "font-semibold text-gray-900 truncate"
    }, j.company || /*#__PURE__*/React.createElement("span", {
      className: "text-gray-400 italic"
    }, "\u672A\u586B\u516C\u53F8\u540D")), j.position_title && /*#__PURE__*/React.createElement("span", {
      className: "text-gray-500 truncate"
    }, "\xB7 ", j.position_title), j.job_type && /*#__PURE__*/React.createElement("span", {
      className: "text-[10px] text-gray-400 uppercase"
    }, j.job_type), processing && /*#__PURE__*/React.createElement("span", {
      className: "text-[10px] text-brand-600 bg-brand-50 px-1.5 py-0.5 rounded animate-pulse"
    }, "AI \u5206\u6790\u4E2D..."), failed && /*#__PURE__*/React.createElement("span", {
      className: "text-[10px] text-rose-600 bg-rose-50 px-1.5 py-0.5 rounded"
    }, "\u89E3\u6790\u5931\u8D25")), /*#__PURE__*/React.createElement("div", {
      className: "text-xs text-gray-500 mt-0.5 line-clamp-1"
    }, j.city && /*#__PURE__*/React.createElement("span", {
      className: "mr-2"
    }, "\uD83D\uDCCD ", j.city), quick?.summary && /*#__PURE__*/React.createElement("span", null, quick.summary), processing && /*#__PURE__*/React.createElement("span", {
      className: "text-gray-400"
    }, "\u540E\u53F0\u8DD1\u4E2D\uFF0C\u7A0D\u7B49\u7247\u523B\u81EA\u52A8\u5237\u65B0"))), j.has_deep_match === 1 && /*#__PURE__*/React.createElement("span", {
      className: "px-1.5 py-0.5 text-[10px] rounded bg-accent-500/10 text-accent-600 font-semibold"
    }, "\u5DF2\u6DF1\u5EA6")), !processing && /*#__PURE__*/React.createElement("div", {
      className: "mt-3 pt-3 border-t border-gray-100 flex items-center gap-1 flex-wrap"
    }, j.position_id ? /*#__PURE__*/React.createElement(Button, {
      size: "sm",
      variant: "ghost",
      onClick: e => {
        e.stopPropagation();
        navigate('positions/' + j.position_id);
      },
      className: "text-emerald-600 hover:bg-emerald-50"
    }, "\u2705 \u5DF2\u5728\u770B\u677F \xB7 \u67E5\u770B") : /*#__PURE__*/React.createElement(Button, {
      size: "sm",
      variant: "ghost",
      onClick: e => {
        e.stopPropagation();
        setBindingJd(j);
      }
    }, "\uD83D\uDCCC \u52A0\u5165\u770B\u677F"), j.has_deep_match !== 1 && /*#__PURE__*/React.createElement(Button, {
      size: "sm",
      variant: "ghost",
      onClick: e => runDeepMatch(j.id, e)
    }, "\uD83D\uDD0D \u6DF1\u5EA6\u5206\u6790"), /*#__PURE__*/React.createElement(Button, {
      size: "sm",
      variant: "ghost",
      onClick: e => {
        e.stopPropagation();
        navigate('jds/' + j.id);
      }
    }, "\uD83D\uDCC4 \u67E5\u770B"), /*#__PURE__*/React.createElement("div", {
      className: "flex-1"
    }), /*#__PURE__*/React.createElement(Button, {
      size: "sm",
      variant: "ghost",
      onClick: e => del(j.id, e),
      className: "text-rose-600 hover:bg-rose-50"
    }, "\u5220\u9664")));
  })), editor && /*#__PURE__*/React.createElement(JDEditor, {
    onClose: () => setEditor(null),
    onSaved: () => {
      setEditor(null);
      load(q);
    }
  }), bindingJd && /*#__PURE__*/React.createElement(BindToPositionModal, {
    jd: bindingJd,
    onClose: () => setBindingJd(null),
    onDone: () => setBindingJd(null)
  }));
}
function JDEditor({
  onClose,
  onSaved
}) {
  const {
    toast
  } = useApp();
  const [rawText, setRawText] = useState('');
  const [company, setCompany] = useState('');
  const [positionTitle, setPositionTitle] = useState('');
  const [createPosition, setCreatePosition] = useState(false);
  const [positionStatus, setPositionStatus] = useState('pending');
  const [submitting, setSubmitting] = useState(false);
  const submit = async () => {
    if (rawText.trim().length < 20) return toast('JD 太短', 'error');
    setSubmitting(true);
    try {
      const body = {
        raw_text: rawText,
        company: company.trim() || undefined,
        position_title: positionTitle.trim() || undefined,
        create_position: createPosition,
        position_status: createPosition ? positionStatus : undefined
      };
      const r = await apiCall('/api/jds', {
        method: 'POST',
        body: JSON.stringify(body)
      });
      if (r.error) {
        toast(r.error, 'error');
      } else {
        toast('JD 已保存，AI 正在后台分析', 'success');
        onSaved();
      }
    } catch (e) {
      handleApiError(e, toast);
    }
    setSubmitting(false);
  };
  return /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: onClose,
    title: "\u7C98\u8D34\u65B0 JD",
    maxWidth: "max-w-2xl"
  }, /*#__PURE__*/React.createElement("div", {
    className: "space-y-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-2 gap-2"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u516C\u53F8\u540D\uFF08\u9009\u586B\uFF09"), /*#__PURE__*/React.createElement("input", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm",
    placeholder: "\u5982\uFF1A\u5B57\u8282\u8DF3\u52A8\uFF08\u4E0D\u586B AI \u81EA\u52A8\u8BC6\u522B\uFF09",
    value: company,
    onChange: e => setCompany(e.target.value)
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u5C97\u4F4D\u540D\uFF08\u9009\u586B\uFF09"), /*#__PURE__*/React.createElement("input", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm",
    placeholder: "\u5982\uFF1AAI\u4EA7\u54C1\u7ECF\u7406\u5B9E\u4E60\u751F",
    value: positionTitle,
    onChange: e => setPositionTitle(e.target.value)
  }))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "JD \u6587\u672C"), /*#__PURE__*/React.createElement("textarea", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm leading-relaxed",
    rows: 7,
    placeholder: "\u4ECE\u62DB\u8058\u7F51\u7AD9/\u90AE\u4EF6/\u516C\u4F17\u53F7\u590D\u5236\u5C97\u4F4D JD \u5168\u6587...",
    value: rawText,
    onChange: e => setRawText(e.target.value)
  }), /*#__PURE__*/React.createElement("div", {
    className: "flex items-center justify-between mt-1"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-[11px] text-gray-300"
  }, "\u624B\u673A\u7AEF App \u4E0D\u652F\u6301\u590D\u5236\uFF1F\u622A\u56FE\u540E\u7528\u7CFB\u7EDF\u81EA\u5E26\u6587\u5B57\u8BC6\u522B\uFF08iPhone \u5B9E\u51B5\u6587\u672C / Android \u667A\u6167\u8BC6\u5C4F\uFF09\uFF0C\u6216\u7535\u8111\u7AEF\u6253\u5F00\u7F51\u9875\u7248\u590D\u5236"), /*#__PURE__*/React.createElement("span", {
    className: "text-xs text-gray-400 flex-shrink-0 ml-2"
  }, rawText.length, " \u5B57"))), /*#__PURE__*/React.createElement("div", {
    className: "rounded-lg border border-gray-200 p-3 bg-gray-50/50"
  }, /*#__PURE__*/React.createElement("label", {
    className: "flex items-center gap-2 text-sm text-gray-700 cursor-pointer"
  }, /*#__PURE__*/React.createElement("input", {
    type: "checkbox",
    checked: createPosition,
    onChange: e => setCreatePosition(e.target.checked),
    className: "w-4 h-4 rounded accent-brand-600"
  }), "\u540C\u6B65\u5230\u5C97\u4F4D\u770B\u677F"), createPosition && /*#__PURE__*/React.createElement("div", {
    className: "mt-2 pl-6"
  }, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u6295\u9012\u72B6\u6001"), /*#__PURE__*/React.createElement("select", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm bg-white",
    value: positionStatus,
    onChange: e => setPositionStatus(e.target.value)
  }, Object.entries(STATUS_LABELS).map(([k, v]) => /*#__PURE__*/React.createElement("option", {
    key: k,
    value: k
  }, v))))), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 justify-end"
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "secondary",
    onClick: onClose
  }, "\u53D6\u6D88"), /*#__PURE__*/React.createElement(Button, {
    variant: "primary",
    onClick: submit,
    disabled: submitting
  }, submitting ? '保存中...' : '保存（AI 后台分析）'))));
}

// ==================== JD 详情页 ====================
function JDDetailPage() {
  const {
    route,
    navigate,
    toast
  } = useApp();
  const id = route.split('/')[1];
  const [jd, setJd] = useState(null);
  const [loading, setLoading] = useState(true);
  const [deepLoading, setDeepLoading] = useState(false);
  const [bindOpen, setBindOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const load = async () => {
    try {
      const r = await apiCall('/api/jds/' + id);
      setJd(r.jd);
    } catch (e) {
      toast(e.message, 'error');
    }
    setLoading(false);
  };
  useEffect(() => {
    setLoading(true);
    load();
  }, [id]);

  // 轮询：processing 状态时每 3 秒自动刷新
  useEffect(() => {
    if (jd?.parse_status !== 'processing') return;
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, [jd?.parse_status]);
  const runDeep = async () => {
    setDeepLoading(true);
    try {
      await apiCall('/api/jds/' + id + '/match', {
        method: 'POST',
        body: JSON.stringify({})
      });
      toast('深度分析完成', 'success');
      load();
    } catch (e) {
      handleApiError(e, toast);
    }
    setDeepLoading(false);
  };
  const rerunQuick = async () => {
    try {
      await apiCall('/api/jds/' + id + '/quick-match', {
        method: 'POST',
        body: JSON.stringify({})
      });
      toast('粗匹配已更新', 'success');
      load();
    } catch (e) {
      handleApiError(e, toast);
    }
  };
  if (loading || !jd) return /*#__PURE__*/React.createElement(Card, {
    className: "p-8 text-center text-gray-400 text-sm"
  }, "\u52A0\u8F7D\u4E2D...");
  const quick = jd.match_quick;
  const deep = jd.match_detail;
  return /*#__PURE__*/React.createElement("div", {
    className: "animate-slide-up space-y-5"
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => navigate('jds'),
    className: "text-sm text-gray-500 hover:text-gray-900 transition"
  }, "\u2190 \u8FD4\u56DE JD \u5E93"), /*#__PURE__*/React.createElement(Card, {
    className: "p-5"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-start gap-3 flex-wrap"
  }, quick && /*#__PURE__*/React.createElement(MatchBand, {
    score: jd.match_score,
    band: quick.band,
    size: "lg",
    showScore: true,
    showLabel: true
  }), /*#__PURE__*/React.createElement("div", {
    className: "flex-1 min-w-0"
  }, /*#__PURE__*/React.createElement("h1", {
    className: "text-xl md:text-2xl font-semibold text-gray-900"
  }, jd.company || '未知公司'), /*#__PURE__*/React.createElement("div", {
    className: "text-sm text-gray-600 mt-0.5"
  }, jd.position_title || '未知岗位', jd.city && /*#__PURE__*/React.createElement("span", {
    className: "ml-2 text-gray-400"
  }, "\uD83D\uDCCD ", jd.city))), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 flex-wrap"
  }, /*#__PURE__*/React.createElement(Button, {
    size: "sm",
    variant: "secondary",
    onClick: () => setEditOpen(true)
  }, "\u7F16\u8F91"), /*#__PURE__*/React.createElement(Button, {
    size: "sm",
    variant: "secondary",
    onClick: rerunQuick
  }, "\u91CD\u7B97\u7C97\u5339\u914D"), /*#__PURE__*/React.createElement(Button, {
    size: "sm",
    variant: "accent",
    onClick: () => setBindOpen(true)
  }, "\u52A0\u5165\u5C97\u4F4D\u770B\u677F")))), quick && /*#__PURE__*/React.createElement(Card, {
    className: "p-5"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center justify-between mb-3"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "font-semibold text-gray-900"
  }, "\u5FEB\u901F\u8BC4\u4F30"), /*#__PURE__*/React.createElement("span", {
    className: "text-xs text-gray-500"
  }, quick.summary)), /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-1 md:grid-cols-2 gap-4 text-sm"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-emerald-700 font-semibold mb-1"
  }, "\u2713 \u5339\u914D\u5173\u952E\u8BCD"), quick.matched_keywords?.length > 0 ? /*#__PURE__*/React.createElement("div", {
    className: "flex gap-1 flex-wrap"
  }, quick.matched_keywords.map((k, i) => /*#__PURE__*/React.createElement("span", {
    key: i,
    className: "px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 text-xs"
  }, k))) : /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-400"
  }, "\u65E0")), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-amber-700 font-semibold mb-1"
  }, "\u2717 \u7F3A\u5931\u5173\u952E\u8BCD"), quick.missing_keywords?.length > 0 ? /*#__PURE__*/React.createElement("div", {
    className: "flex gap-1 flex-wrap"
  }, quick.missing_keywords.map((k, i) => /*#__PURE__*/React.createElement("span", {
    key: i,
    className: "px-2 py-0.5 rounded bg-amber-50 text-amber-700 text-xs"
  }, k))) : /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-400"
  }, "\u65E0")))), /*#__PURE__*/React.createElement(Card, {
    className: "p-5"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center justify-between mb-3"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "font-semibold text-gray-900"
  }, "\u6DF1\u5EA6\u5339\u914D\u5206\u6790"), /*#__PURE__*/React.createElement("span", {
    className: "text-xs text-gray-500"
  }, "Pro \xB7 \u6D88\u8017 1 \u6B21\u6DF1\u5EA6\u914D\u989D")), !deep ? /*#__PURE__*/React.createElement("div", {
    className: "py-6 text-center"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-sm text-gray-500 mb-3"
  }, "AI \u7ED3\u5408\u7B80\u5386\u539F\u6587\u505A\u8BC1\u636E\u7EA7\u5206\u6790"), /*#__PURE__*/React.createElement(Button, {
    variant: "primary",
    onClick: runDeep,
    disabled: deepLoading
  }, deepLoading ? 'AI 分析中（约 20 秒）...' : '生成深度分析')) : /*#__PURE__*/React.createElement("div", {
    className: "space-y-4 text-sm"
  }, /*#__PURE__*/React.createElement("div", {
    className: "p-3 rounded-lg bg-gray-50 text-gray-800 italic"
  }, deep.summary), deep.matched?.length > 0 && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "text-xs font-semibold text-emerald-700 mb-2"
  }, "\u2713 \u5339\u914D\u70B9\uFF08", deep.matched.length, "\uFF09"), /*#__PURE__*/React.createElement("div", {
    className: "space-y-2"
  }, deep.matched.map((m, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    className: "border-l-2 border-emerald-400 pl-3 text-xs"
  }, /*#__PURE__*/React.createElement("div", {
    className: "font-medium text-gray-900"
  }, typeof m === 'string' ? m : m.point), m.resume_evidence && /*#__PURE__*/React.createElement("div", {
    className: "text-gray-500 mt-0.5"
  }, "\uD83D\uDCC4 ", m.resume_evidence), m.jd_evidence && /*#__PURE__*/React.createElement("div", {
    className: "text-gray-500"
  }, "\uD83D\uDCBC ", m.jd_evidence))))), deep.missing?.length > 0 && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "text-xs font-semibold text-amber-700 mb-2"
  }, "\u2717 \u7F3A\u5931\u80FD\u529B\uFF08", deep.missing.length, "\uFF09"), /*#__PURE__*/React.createElement("div", {
    className: "space-y-2"
  }, deep.missing.map((m, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    className: "border-l-2 border-amber-400 pl-3 text-xs"
  }, /*#__PURE__*/React.createElement("div", {
    className: "font-medium text-gray-900 flex items-center gap-2 flex-wrap"
  }, typeof m === 'string' ? m : m.gap, m.severity && /*#__PURE__*/React.createElement("span", {
    className: 'px-1.5 py-0.5 rounded text-[10px] ' + (m.severity === 'critical' ? 'bg-rose-100 text-rose-700' : m.severity === 'major' ? 'bg-amber-100 text-amber-700' : 'bg-gray-100 text-gray-600')
  }, m.severity === 'critical' ? '严重' : m.severity === 'major' ? '主要' : '次要')), m.jd_requirement && /*#__PURE__*/React.createElement("div", {
    className: "text-gray-500 mt-0.5"
  }, "JD \u8981\u6C42\uFF1A", m.jd_requirement))))), deep.red_flags?.length > 0 && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "text-xs font-semibold text-rose-700 mb-2"
  }, "\u26A0\uFE0F \u98CE\u9669\u70B9"), /*#__PURE__*/React.createElement("ul", {
    className: "text-xs text-gray-700 ml-4 list-disc space-y-1"
  }, deep.red_flags.map((r, i) => /*#__PURE__*/React.createElement("li", {
    key: i
  }, r)))), deep.suggestions?.length > 0 && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "text-xs font-semibold text-brand-700 mb-2"
  }, "\uD83D\uDCA1 \u6539\u8FDB\u5EFA\u8BAE"), /*#__PURE__*/React.createElement("ul", {
    className: "text-xs text-gray-700 ml-4 list-disc space-y-1"
  }, deep.suggestions.map((s, i) => /*#__PURE__*/React.createElement("li", {
    key: i
  }, s)))), /*#__PURE__*/React.createElement("div", {
    className: "pt-2 border-t border-gray-100"
  }, /*#__PURE__*/React.createElement(Button, {
    size: "sm",
    variant: "ghost",
    onClick: runDeep,
    disabled: deepLoading
  }, deepLoading ? '重新分析中...' : '重新分析')))), /*#__PURE__*/React.createElement(Card, {
    className: "p-5"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center justify-between mb-3"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "font-semibold text-gray-900"
  }, "JD \u8BE6\u60C5")), jd.parsed ? /*#__PURE__*/React.createElement("div", {
    className: "space-y-3 text-sm"
  }, jd.parsed.responsibilities?.length > 0 && /*#__PURE__*/React.createElement(Section, {
    title: "\u5C97\u4F4D\u804C\u8D23"
  }, /*#__PURE__*/React.createElement("ul", {
    className: "text-xs text-gray-700 ml-4 list-disc space-y-0.5"
  }, jd.parsed.responsibilities.map((r, i) => /*#__PURE__*/React.createElement("li", {
    key: i
  }, r)))), jd.parsed.requirements?.length > 0 && /*#__PURE__*/React.createElement(Section, {
    title: "\u4EFB\u804C\u8981\u6C42"
  }, /*#__PURE__*/React.createElement("ul", {
    className: "text-xs text-gray-700 ml-4 list-disc space-y-0.5"
  }, jd.parsed.requirements.map((r, i) => /*#__PURE__*/React.createElement("li", {
    key: i
  }, r)))), jd.parsed.preferred?.length > 0 && /*#__PURE__*/React.createElement(Section, {
    title: "\u52A0\u5206\u9879"
  }, /*#__PURE__*/React.createElement("ul", {
    className: "text-xs text-gray-700 ml-4 list-disc space-y-0.5"
  }, jd.parsed.preferred.map((r, i) => /*#__PURE__*/React.createElement("li", {
    key: i
  }, r)))), jd.parsed.tech_stack?.length > 0 && /*#__PURE__*/React.createElement(Section, {
    title: "\u6280\u672F\u6808"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex gap-1 flex-wrap"
  }, jd.parsed.tech_stack.map((t, i) => /*#__PURE__*/React.createElement("span", {
    key: i,
    className: "px-2 py-0.5 rounded bg-brand-50 text-brand-700 text-xs"
  }, t)))), /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-3 gap-2 text-xs pt-2 border-t border-gray-100"
  }, jd.parsed.salary && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("span", {
    className: "text-gray-400"
  }, "\u85AA\u8D44\uFF1A"), jd.parsed.salary), jd.parsed.duration && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("span", {
    className: "text-gray-400"
  }, "\u65F6\u957F\uFF1A"), jd.parsed.duration), jd.parsed.working_days && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("span", {
    className: "text-gray-400"
  }, "\u5230\u5C97\uFF1A"), jd.parsed.working_days))) : /*#__PURE__*/React.createElement("pre", {
    className: "text-xs text-gray-700 bg-gray-50 p-3 rounded whitespace-pre-wrap leading-relaxed"
  }, jd.raw_text)), bindOpen && /*#__PURE__*/React.createElement(BindToPositionModal, {
    jd: jd,
    onClose: () => setBindOpen(false),
    onDone: () => setBindOpen(false)
  }), editOpen && /*#__PURE__*/React.createElement(JDEditModal, {
    jd: jd,
    onClose: () => setEditOpen(false),
    onSaved: () => {
      setEditOpen(false);
      load();
    }
  }));
}
function JDEditModal({
  jd,
  onClose,
  onSaved
}) {
  const {
    toast
  } = useApp();
  const [company, setCompany] = useState(jd.company || '');
  const [positionTitle, setPositionTitle] = useState(jd.position_title || '');
  const [rawText, setRawText] = useState(jd.raw_text || '');
  const [submitting, setSubmitting] = useState(false);
  const submit = async () => {
    setSubmitting(true);
    try {
      const body = {};
      if (company !== (jd.company || '')) body.company = company;
      if (positionTitle !== (jd.position_title || '')) body.position_title = positionTitle;
      if (rawText !== jd.raw_text) body.raw_text = rawText;
      if (Object.keys(body).length === 0) {
        toast('没有改动', 'info');
        onClose();
        return;
      }
      const r = await apiCall('/api/jds/' + jd.id, {
        method: 'PUT',
        body: JSON.stringify(body)
      });
      if (r.reparsing) toast('已保存，AI 正在重新分析', 'success');else toast('已更新', 'success');
      onSaved();
    } catch (e) {
      handleApiError(e, toast);
    }
    setSubmitting(false);
  };
  return /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: onClose,
    title: "\u7F16\u8F91 JD",
    maxWidth: "max-w-2xl"
  }, /*#__PURE__*/React.createElement("div", {
    className: "space-y-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-2 gap-2"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u516C\u53F8\u540D"), /*#__PURE__*/React.createElement("input", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm",
    value: company,
    onChange: e => setCompany(e.target.value)
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u5C97\u4F4D\u540D"), /*#__PURE__*/React.createElement("input", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm",
    value: positionTitle,
    onChange: e => setPositionTitle(e.target.value)
  }))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "JD \u539F\u6587\uFF08\u4FEE\u6539\u4F1A\u89E6\u53D1 AI \u91CD\u65B0\u5206\u6790\uFF09"), /*#__PURE__*/React.createElement("textarea", {
    rows: 7,
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm leading-relaxed",
    value: rawText,
    onChange: e => setRawText(e.target.value)
  }), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-400 mt-1"
  }, rawText.length, " \u5B57")), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 justify-end"
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "secondary",
    onClick: onClose
  }, "\u53D6\u6D88"), /*#__PURE__*/React.createElement(Button, {
    variant: "primary",
    onClick: submit,
    disabled: submitting
  }, submitting ? '保存中...' : '保存'))));
}
function BindToPositionModal({
  jd,
  onClose,
  onDone
}) {
  const {
    toast,
    navigate
  } = useApp();
  const [status, setStatus] = useState('pending');
  const [submitting, setSubmitting] = useState(false);
  const submit = async () => {
    setSubmitting(true);
    try {
      const r = await apiCall('/api/positions', {
        method: 'POST',
        body: JSON.stringify({
          jd_id: jd.id,
          company: jd.company,
          position_title: jd.position_title,
          status
        })
      });
      toast('已加入岗位看板', 'success');
      navigate('positions/' + r.id);
      onDone();
    } catch (e) {
      if (e.status === 409 && e.data?.position_id) {
        toast('这个岗位已经在看板里啦', 'info');
        navigate('positions/' + e.data.position_id);
        onDone();
      } else {
        handleApiError(e, toast);
      }
    }
    setSubmitting(false);
  };
  return /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: onClose,
    title: "\u52A0\u5165\u5C97\u4F4D\u770B\u677F"
  }, /*#__PURE__*/React.createElement("div", {
    className: "space-y-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-sm text-gray-700"
  }, "\u5C06 ", /*#__PURE__*/React.createElement("b", null, jd.company, " \xB7 ", jd.position_title), " \u52A0\u5165\u5C97\u4F4D\u770B\u677F"), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u521D\u59CB\u72B6\u6001"), /*#__PURE__*/React.createElement("select", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm bg-white",
    value: status,
    onChange: e => setStatus(e.target.value)
  }, /*#__PURE__*/React.createElement("option", {
    value: "pending"
  }, "\u5F85\u6295\u9012"), /*#__PURE__*/React.createElement("option", {
    value: "applied"
  }, "\u5DF2\u6295\u9012"), /*#__PURE__*/React.createElement("option", {
    value: "written_test"
  }, "\u7B14\u8BD5\u4E2D"), /*#__PURE__*/React.createElement("option", {
    value: "interview_1"
  }, "\u4E00\u9762"))), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 justify-end"
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "secondary",
    onClick: onClose
  }, "\u53D6\u6D88"), /*#__PURE__*/React.createElement(Button, {
    variant: "primary",
    onClick: submit,
    disabled: submitting
  }, "\u52A0\u5165"))));
}

// ==================== 页面：岗位看板 ====================
const POSITION_LANES = [{
  key: 'pending',
  label: '待投递',
  statuses: ['pending']
}, {
  key: 'applied',
  label: '已投递',
  statuses: ['applied']
}, {
  key: 'test',
  label: '笔试/面试',
  statuses: ['written_test', 'interview_1', 'interview_2', 'interview_3plus']
}, {
  key: 'offer',
  label: 'Offer/入职',
  statuses: ['offer', 'onboard']
}, {
  key: 'closed',
  label: '已结束',
  statuses: ['rejected', 'withdrawn']
}];
function PositionsPage() {
  const {
    toast,
    navigate
  } = useApp();
  const [list, setList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [newModal, setNewModal] = useState(false);
  const load = async () => {
    setLoading(true);
    try {
      const r = await apiCall('/api/positions');
      setList(r.positions || []);
    } catch (e) {
      toast(e.message, 'error');
    }
    setLoading(false);
  };
  useEffect(() => {
    load();
  }, []);
  const groups = useMemo(() => {
    const m = {};
    for (const lane of POSITION_LANES) m[lane.key] = [];
    for (const p of list) {
      for (const lane of POSITION_LANES) {
        if (lane.statuses.includes(p.status)) {
          m[lane.key].push(p);
          break;
        }
      }
    }
    return m;
  }, [list]);
  return /*#__PURE__*/React.createElement("div", {
    className: "animate-slide-up"
  }, /*#__PURE__*/React.createElement(PageHeader, {
    title: "\u5C97\u4F4D\u770B\u677F",
    desc: list.length + ' 个岗位 · 点击进入详情',
    action: /*#__PURE__*/React.createElement(Button, {
      variant: "primary",
      onClick: () => setNewModal(true)
    }, /*#__PURE__*/React.createElement(Icon.Plus, {
      className: "w-4 h-4 mr-1"
    }), " \u624B\u52A8\u6DFB\u52A0")
  }), loading ? /*#__PURE__*/React.createElement(Card, {
    className: "p-8 text-center text-gray-400 text-sm"
  }, "\u52A0\u8F7D\u4E2D...") : list.length === 0 ? /*#__PURE__*/React.createElement(Card, {
    className: "p-0"
  }, /*#__PURE__*/React.createElement(EmptyState, {
    icon: "\uD83D\uDCCC",
    title: "\u8FD8\u6CA1\u6709\u5C97\u4F4D",
    desc: "\u4ECE JD \u5E93\u9009\u300C\u52A0\u5165\u770B\u677F\u300D\uFF0C\u6216\u624B\u52A8\u6DFB\u52A0\u4E00\u4E2A\u4F60\u6B63\u5728\u51C6\u5907\u7684\u5C97\u4F4D",
    action: /*#__PURE__*/React.createElement("div", {
      className: "flex gap-2 justify-center"
    }, /*#__PURE__*/React.createElement(Button, {
      variant: "secondary",
      onClick: () => navigate('jds')
    }, "\u53BB JD \u5E93"), /*#__PURE__*/React.createElement(Button, {
      variant: "primary",
      onClick: () => setNewModal(true)
    }, "\u624B\u52A8\u6DFB\u52A0"))
  })) : /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-1 md:grid-cols-5 gap-3"
  }, POSITION_LANES.map(lane => /*#__PURE__*/React.createElement("div", {
    key: lane.key,
    className: "min-w-0"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center justify-between mb-2 px-1"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-sm font-semibold text-gray-700"
  }, lane.label), /*#__PURE__*/React.createElement("span", {
    className: "text-xs text-gray-400"
  }, groups[lane.key].length)), /*#__PURE__*/React.createElement("div", {
    className: "space-y-2"
  }, groups[lane.key].map(p => /*#__PURE__*/React.createElement(Card, {
    key: p.id,
    clickable: true,
    onClick: () => navigate('positions/' + p.id),
    className: "p-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "font-medium text-sm text-gray-900 truncate"
  }, p.company), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-500 truncate"
  }, p.position_title), /*#__PURE__*/React.createElement("div", {
    className: "mt-2 flex items-center gap-2"
  }, /*#__PURE__*/React.createElement(StatusBadge, {
    status: p.status
  }), p.review_count > 0 && /*#__PURE__*/React.createElement("span", {
    className: "text-[10px] text-gray-400"
  }, "\uD83D\uDCDD ", p.review_count)))), groups[lane.key].length === 0 && /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-300 text-center py-3"
  }, "\u2014"))))), newModal && /*#__PURE__*/React.createElement(PositionCreateModal, {
    onClose: () => setNewModal(false),
    onDone: () => {
      setNewModal(false);
      load();
    }
  }));
}
function PositionCreateModal({
  onClose,
  onDone
}) {
  const {
    toast
  } = useApp();
  const [form, setForm] = useState({
    company: '',
    position_title: '',
    status: 'pending'
  });
  const [submitting, setSubmitting] = useState(false);
  const submit = async () => {
    if (!form.company || !form.position_title) return toast('公司和岗位名必填', 'error');
    setSubmitting(true);
    try {
      await apiCall('/api/positions', {
        method: 'POST',
        body: JSON.stringify(form)
      });
      toast('已添加', 'success');
      onDone();
    } catch (e) {
      toast(e.message, 'error');
    }
    setSubmitting(false);
  };
  return /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: onClose,
    title: "\u624B\u52A8\u6DFB\u52A0\u5C97\u4F4D"
  }, /*#__PURE__*/React.createElement("div", {
    className: "space-y-3"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u516C\u53F8"), /*#__PURE__*/React.createElement("input", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm",
    value: form.company,
    onChange: e => setForm({
      ...form,
      company: e.target.value
    })
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u5C97\u4F4D\u540D"), /*#__PURE__*/React.createElement("input", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm",
    value: form.position_title,
    onChange: e => setForm({
      ...form,
      position_title: e.target.value
    })
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u521D\u59CB\u72B6\u6001"), /*#__PURE__*/React.createElement("select", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm bg-white",
    value: form.status,
    onChange: e => setForm({
      ...form,
      status: e.target.value
    })
  }, Object.entries(STATUS_LABELS).map(([k, v]) => /*#__PURE__*/React.createElement("option", {
    key: k,
    value: k
  }, v)))), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 justify-end"
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "secondary",
    onClick: onClose
  }, "\u53D6\u6D88"), /*#__PURE__*/React.createElement(Button, {
    variant: "primary",
    onClick: submit,
    disabled: submitting
  }, "\u6DFB\u52A0"))));
}

// ==================== 岗位详情 ====================
function PositionDetailPage() {
  const {
    route,
    navigate,
    toast
  } = useApp();
  const id = route.split('/')[1];
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [statusModal, setStatusModal] = useState(false);
  const [roundModal, setRoundModal] = useState(null);
  const [reviewModal, setReviewModal] = useState(null);
  const [reviewViewing, setReviewViewing] = useState(null);
  const load = async () => {
    setLoading(true);
    try {
      const r = await apiCall('/api/positions/' + id);
      setData(r);
    } catch (e) {
      toast(e.message, 'error');
    }
    setLoading(false);
  };
  useEffect(() => {
    load();
  }, [id]);
  const del = async () => {
    if (!confirm('删除这个岗位？所有关联的面试轮次和复盘也会一并删除')) return;
    try {
      await apiCall('/api/positions/' + id, {
        method: 'DELETE'
      });
      toast('已删除', 'success');
      navigate('positions');
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  const updateStatus = async newStatus => {
    try {
      await apiCall('/api/positions/' + id, {
        method: 'PUT',
        body: JSON.stringify({
          status: newStatus
        })
      });
      toast('状态已更新', 'success');
      setStatusModal(false);
      load();
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  if (loading || !data) return /*#__PURE__*/React.createElement(Card, {
    className: "p-8 text-center text-gray-400 text-sm"
  }, "\u52A0\u8F7D\u4E2D...");
  const p = data.position;
  return /*#__PURE__*/React.createElement("div", {
    className: "animate-slide-up space-y-5"
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => navigate('positions'),
    className: "text-sm text-gray-500 hover:text-gray-900 transition"
  }, "\u2190 \u8FD4\u56DE\u5C97\u4F4D\u770B\u677F"), /*#__PURE__*/React.createElement(Card, {
    className: "p-5"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-start gap-3 flex-wrap"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex-1 min-w-0"
  }, /*#__PURE__*/React.createElement("h1", {
    className: "text-xl md:text-2xl font-semibold text-gray-900"
  }, p.company), /*#__PURE__*/React.createElement("div", {
    className: "text-sm text-gray-600 mt-0.5"
  }, p.position_title), /*#__PURE__*/React.createElement("div", {
    className: "mt-3 flex items-center gap-2 flex-wrap"
  }, /*#__PURE__*/React.createElement(StatusBadge, {
    status: p.status
  }), p.applied_at && /*#__PURE__*/React.createElement("span", {
    className: "text-xs text-gray-500"
  }, "\u6295\u9012\u4E8E ", new Date(p.applied_at).toLocaleDateString('zh-CN')))), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 flex-wrap"
  }, /*#__PURE__*/React.createElement(Button, {
    size: "sm",
    variant: "secondary",
    onClick: () => setStatusModal(true)
  }, "\u66F4\u65B0\u72B6\u6001"), /*#__PURE__*/React.createElement(Button, {
    size: "sm",
    variant: "ghost",
    onClick: del,
    className: "text-rose-600 hover:bg-rose-50"
  }, "\u5220\u9664"))), p.notes && /*#__PURE__*/React.createElement("div", {
    className: "mt-4 pt-4 border-t border-gray-100 text-xs text-gray-600 italic"
  }, p.notes)), data.jd && /*#__PURE__*/React.createElement(Card, {
    clickable: true,
    onClick: () => navigate('jds/' + data.jd.id),
    className: "p-4 flex items-center gap-3"
  }, /*#__PURE__*/React.createElement(MatchBand, {
    score: data.jd.match_score,
    band: scoreToBand(data.jd.match_score),
    size: "md"
  }), /*#__PURE__*/React.createElement("div", {
    className: "flex-1 text-sm"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-gray-500 text-xs"
  }, "\u5173\u8054 JD"), /*#__PURE__*/React.createElement("div", {
    className: "font-medium text-gray-900"
  }, data.jd.company || '未填公司名', " \xB7 ", data.jd.position_title || '未填岗位')), /*#__PURE__*/React.createElement(Button, {
    size: "sm",
    variant: "ghost",
    onClick: e => {
      e.stopPropagation();
      navigate('jds/' + data.jd.id);
    }
  }, "\u7F16\u8F91 JD \u2192")), /*#__PURE__*/React.createElement(Card, {
    className: "p-5"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center justify-between mb-3"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "font-semibold text-gray-900"
  }, "\u9762\u8BD5\u8F6E\u6B21"), /*#__PURE__*/React.createElement(Button, {
    size: "sm",
    variant: "secondary",
    onClick: () => setRoundModal({})
  }, /*#__PURE__*/React.createElement(Icon.Plus, {
    className: "w-3.5 h-3.5 mr-1"
  }), " \u6DFB\u52A0")), data.rounds.length === 0 ? /*#__PURE__*/React.createElement("div", {
    className: "text-sm text-gray-400 py-3"
  }, "\u8FD8\u6CA1\u6709\u9762\u8BD5\u8BB0\u5F55") : /*#__PURE__*/React.createElement("div", {
    className: "space-y-2"
  }, data.rounds.map(r => /*#__PURE__*/React.createElement("div", {
    key: r.id,
    className: "flex items-center gap-3 p-3 rounded-lg border border-gray-100 hover:bg-gray-50 transition"
  }, /*#__PURE__*/React.createElement("div", {
    className: "w-9 h-9 rounded-full bg-purple-50 text-purple-700 font-bold text-sm flex items-center justify-center"
  }, r.round_number), /*#__PURE__*/React.createElement("div", {
    className: "flex-1 min-w-0"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-sm font-medium text-gray-900"
  }, "\u7B2C ", r.round_number, " \u8F6E", r.round_type && /*#__PURE__*/React.createElement("span", {
    className: "ml-2 text-xs text-gray-500"
  }, r.round_type)), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-500"
  }, r.scheduled_at ? new Date(r.scheduled_at).toLocaleString('zh-CN') : '未安排时间', r.result && r.result !== 'pending' && /*#__PURE__*/React.createElement("span", {
    className: "ml-2"
  }, "\xB7 ", r.result))), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-1 flex-wrap"
  }, /*#__PURE__*/React.createElement(Button, {
    size: "sm",
    variant: "ghost",
    onClick: () => setReviewModal({
      roundId: r.id
    })
  }, "\uD83D\uDCDD \u590D\u76D8"), /*#__PURE__*/React.createElement(Button, {
    size: "sm",
    variant: "ghost",
    onClick: () => setRoundModal({
      data: r
    })
  }, "\u7F16\u8F91")))))), /*#__PURE__*/React.createElement(Card, {
    className: "p-5"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center justify-between mb-3"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "font-semibold text-gray-900"
  }, "\u590D\u76D8\u8BB0\u5F55"), /*#__PURE__*/React.createElement(Button, {
    size: "sm",
    variant: "secondary",
    onClick: () => setReviewModal({})
  }, /*#__PURE__*/React.createElement(Icon.Plus, {
    className: "w-3.5 h-3.5 mr-1"
  }), " \u7C98\u8D34\u590D\u76D8")), data.reviews.length === 0 ? /*#__PURE__*/React.createElement("div", {
    className: "text-sm text-gray-400 py-3"
  }, "\u8FD8\u6CA1\u6709\u590D\u76D8\u3002\u9762\u8BD5\u7ED3\u675F\u540E\u7C98\u8D34\u56DE\u5FC6\u6587\u672C\uFF0CAI \u5E2E\u4F60\u5206\u6790") : /*#__PURE__*/React.createElement("div", {
    className: "space-y-2"
  }, data.reviews.map(r => /*#__PURE__*/React.createElement("div", {
    key: r.id,
    onClick: () => setReviewViewing(r.id),
    className: "card-apple clickable p-3 rounded-lg border border-gray-100 hover:bg-gray-50 cursor-pointer"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-2 mb-1 flex-wrap"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-xs font-medium text-gray-900"
  }, relTime(r.created_at)), r.round_id && /*#__PURE__*/React.createElement("span", {
    className: "text-[10px] text-purple-600 bg-purple-50 px-1 rounded"
  }, "\u5173\u8054\u8F6E\u6B21"), r.parse_status === 'failed' && /*#__PURE__*/React.createElement("span", {
    className: "text-[10px] text-rose-500"
  }, "\u89E3\u6790\u5931\u8D25"), r.parse_status === 'processing' && /*#__PURE__*/React.createElement("span", {
    className: "text-[10px] text-gray-400"
  }, "\u89E3\u6790\u4E2D")), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-600 line-clamp-2"
  }, r.preview))))), statusModal && /*#__PURE__*/React.createElement(StatusUpdateModal, {
    current: p.status,
    onClose: () => setStatusModal(false),
    onUpdate: updateStatus
  }), roundModal && /*#__PURE__*/React.createElement(RoundEditorModal, {
    positionId: id,
    data: roundModal.data,
    onClose: () => setRoundModal(null),
    onDone: () => {
      setRoundModal(null);
      load();
    }
  }), reviewModal && /*#__PURE__*/React.createElement(ReviewEditorModal, {
    positionId: id,
    defaultRoundId: reviewModal.roundId,
    rounds: data.rounds,
    onClose: () => setReviewModal(null),
    onDone: () => {
      setReviewModal(null);
      load();
    }
  }), reviewViewing && /*#__PURE__*/React.createElement(ReviewViewer, {
    reviewId: reviewViewing,
    onClose: () => setReviewViewing(null)
  }));
}
function StatusUpdateModal({
  current,
  onClose,
  onUpdate
}) {
  const [status, setStatus] = useState(current);
  // v3.2: 基于当前状态推荐合理下一步
  const RECOMMENDED_NEXT = {
    pending: 'applied',
    applied: 'written_test',
    written_test: 'interview_1',
    interview_1: 'interview_2',
    interview_2: 'interview_3plus',
    interview_3plus: 'offer',
    offer: 'onboard'
  };
  return /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: onClose,
    title: "\u66F4\u65B0\u5C97\u4F4D\u72B6\u6001"
  }, /*#__PURE__*/React.createElement("div", {
    className: "space-y-3"
  }, /*#__PURE__*/React.createElement("select", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm bg-white",
    value: status,
    onChange: e => setStatus(e.target.value)
  }, Object.entries(STATUS_LABELS).map(([k, v]) => /*#__PURE__*/React.createElement("option", {
    key: k,
    value: k
  }, v, RECOMMENDED_NEXT[current] === k ? ' (推荐)' : ''))), RECOMMENDED_NEXT[current] && /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-400 leading-relaxed"
  }, "\uD83D\uDCA1 \u5F53\u524D\u72B6\u6001\u901A\u5E38\u4E0B\u4E00\u6B65\u662F ", /*#__PURE__*/React.createElement("strong", {
    className: "text-brand-600"
  }, STATUS_LABELS[RECOMMENDED_NEXT[current]]), "\uFF0C\u4E5F\u53EF\u4EE5\u624B\u52A8\u5207\u6362\u3002"), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 justify-end"
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "secondary",
    onClick: onClose
  }, "\u53D6\u6D88"), /*#__PURE__*/React.createElement(Button, {
    variant: "primary",
    onClick: () => onUpdate(status)
  }, "\u66F4\u65B0"))));
}
function RoundEditorModal({
  positionId,
  data,
  onClose,
  onDone
}) {
  const {
    toast
  } = useApp();
  const [form, setForm] = useState(data || {
    round_number: null,
    round_type: '',
    scheduled_at: '',
    result: 'pending',
    notes: ''
  });
  const [submitting, setSubmitting] = useState(false);
  const submit = async () => {
    setSubmitting(true);
    try {
      const payload = {
        ...form
      };
      if (payload.scheduled_at && !payload.scheduled_at.endsWith(':00')) payload.scheduled_at += ':00';
      if (data?.id) await apiCall('/api/rounds/' + data.id, {
        method: 'PUT',
        body: JSON.stringify(payload)
      });else await apiCall('/api/positions/' + positionId + '/rounds', {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      toast(data?.id ? '已更新' : '已添加', 'success');
      onDone();
    } catch (e) {
      toast(e.message, 'error');
    }
    setSubmitting(false);
  };
  const del = async () => {
    if (!confirm('删除这轮面试？')) return;
    try {
      await apiCall('/api/rounds/' + data.id, {
        method: 'DELETE'
      });
      toast('已删除', 'success');
      onDone();
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  return /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: onClose,
    title: data?.id ? '编辑面试轮次' : '新增面试轮次'
  }, /*#__PURE__*/React.createElement("div", {
    className: "space-y-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-2 gap-3"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u7B2C\u51E0\u8F6E"), /*#__PURE__*/React.createElement("input", {
    type: "number",
    min: "1",
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm",
    placeholder: "\u4E0D\u586B\u81EA\u52A8\u9012\u589E",
    value: form.round_number || '',
    onChange: e => setForm({
      ...form,
      round_number: e.target.value ? Number(e.target.value) : null
    })
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u5F62\u5F0F"), /*#__PURE__*/React.createElement("select", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm bg-white",
    value: form.round_type || '',
    onChange: e => setForm({
      ...form,
      round_type: e.target.value
    })
  }, /*#__PURE__*/React.createElement("option", {
    value: ""
  }, "\u672A\u6307\u5B9A"), /*#__PURE__*/React.createElement("option", {
    value: "phone"
  }, "\u7535\u8BDD\u9762"), /*#__PURE__*/React.createElement("option", {
    value: "video"
  }, "\u89C6\u9891\u9762"), /*#__PURE__*/React.createElement("option", {
    value: "onsite"
  }, "\u73B0\u573A\u9762"), /*#__PURE__*/React.createElement("option", {
    value: "group"
  }, "\u7FA4\u9762"), /*#__PURE__*/React.createElement("option", {
    value: "hr"
  }, "HR \u9762")))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u65F6\u95F4"), /*#__PURE__*/React.createElement("input", {
    type: "datetime-local",
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm",
    value: form.scheduled_at?.slice(0, 16) || '',
    onChange: e => setForm({
      ...form,
      scheduled_at: e.target.value || null
    })
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u7ED3\u679C"), /*#__PURE__*/React.createElement("select", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm bg-white",
    value: form.result || 'pending',
    onChange: e => setForm({
      ...form,
      result: e.target.value
    })
  }, /*#__PURE__*/React.createElement("option", {
    value: "pending"
  }, "\u5F85\u9762\u8BD5"), /*#__PURE__*/React.createElement("option", {
    value: "pending_feedback"
  }, "\u5DF2\u9762\u8BD5\uFF0C\u7B49\u53CD\u9988"), /*#__PURE__*/React.createElement("option", {
    value: "passed"
  }, "\u901A\u8FC7"), /*#__PURE__*/React.createElement("option", {
    value: "failed"
  }, "\u672A\u901A\u8FC7"))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u5907\u6CE8"), /*#__PURE__*/React.createElement("textarea", {
    rows: 3,
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm",
    value: form.notes || '',
    onChange: e => setForm({
      ...form,
      notes: e.target.value
    })
  })), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 justify-end pt-2"
  }, data?.id && /*#__PURE__*/React.createElement(Button, {
    variant: "ghost",
    onClick: del,
    className: "text-rose-600 hover:bg-rose-50"
  }, "\u5220\u9664"), /*#__PURE__*/React.createElement("div", {
    className: "flex-1"
  }), /*#__PURE__*/React.createElement(Button, {
    variant: "secondary",
    onClick: onClose
  }, "\u53D6\u6D88"), /*#__PURE__*/React.createElement(Button, {
    variant: "primary",
    onClick: submit,
    disabled: submitting
  }, submitting ? '保存中...' : '保存'))));
}
function ReviewEditorModal({
  positionId,
  defaultRoundId,
  rounds,
  onClose,
  onDone
}) {
  const {
    toast
  } = useApp();
  const [roundId, setRoundId] = useState(defaultRoundId || '');
  const [rawText, setRawText] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const submit = async () => {
    if (rawText.trim().length < 30) return toast('复盘内容至少 30 字', 'error');
    setSubmitting(true);
    try {
      const r = await apiCall('/api/reviews', {
        method: 'POST',
        body: JSON.stringify({
          position_id: positionId,
          round_id: roundId || null,
          raw_text: rawText
        })
      });
      if (r.error) {
        toast(r.error, 'error');
      } else {
        toast('AI 复盘分析完成', 'success');
        onDone();
      }
    } catch (e) {
      handleApiError(e, toast);
    }
    setSubmitting(false);
  };
  return /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: onClose,
    title: "\u7C98\u8D34\u590D\u76D8\u6587\u672C",
    maxWidth: "max-w-2xl"
  }, /*#__PURE__*/React.createElement("div", {
    className: "space-y-3"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u5173\u8054\u8F6E\u6B21\uFF08\u9009\u586B\uFF09"), /*#__PURE__*/React.createElement("select", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm bg-white",
    value: roundId,
    onChange: e => setRoundId(e.target.value)
  }, /*#__PURE__*/React.createElement("option", {
    value: ""
  }, "\u4E0D\u5173\u8054\u7279\u5B9A\u8F6E\u6B21"), rounds.map(r => /*#__PURE__*/React.createElement("option", {
    key: r.id,
    value: r.id
  }, "\u7B2C ", r.round_number, " \u8F6E", r.round_type ? ' · ' + r.round_type : '')))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u590D\u76D8\u6587\u672C\uFF08\u95EE\u7B54\u3001\u611F\u89C9\u3001\u5370\u8C61\uFF09"), /*#__PURE__*/React.createElement("textarea", {
    rows: 7,
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm leading-relaxed",
    placeholder: "粘贴面试的完整回忆，越详细越好。示例：\n面试官问：你为什么选择产品方向？\n我答：因为我觉得...",
    value: rawText,
    onChange: e => setRawText(e.target.value)
  }), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-400 mt-1"
  }, rawText.length, " \u5B57 \xB7 \u5EFA\u8BAE 300 \u5B57\u4EE5\u4E0A")), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 justify-end pt-2"
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "secondary",
    onClick: onClose
  }, "\u53D6\u6D88"), /*#__PURE__*/React.createElement(Button, {
    variant: "primary",
    onClick: submit,
    disabled: submitting
  }, submitting ? 'AI 分析中（约 30 秒）...' : '生成分析'))));
}
function ReviewViewer({
  reviewId,
  onClose
}) {
  const {
    toast
  } = useApp();
  const [review, setReview] = useState(null);
  const [error, setError] = useState(false);
  const [shareMode, setShareMode] = useState(null);
  const [sharePreview, setSharePreview] = useState('');
  const [shareLoading, setShareLoading] = useState(false);
  useEffect(() => {
    apiCall('/api/reviews/' + reviewId).then(r => setReview(r.review)).catch(() => setError(true));
  }, [reviewId]);
  const doShareGenerate = async mode => {
    setShareMode(mode);
    setShareLoading(true);
    try {
      const r = await apiCall('/api/cards/generate', {
        method: 'POST',
        body: JSON.stringify({
          review_id: reviewId,
          card_mode: mode
        })
      });
      setSharePreview(r.card_body || '');
    } catch (e) {
      toast(e.message, 'error');
      setShareMode(null);
    }
    setShareLoading(false);
  };
  const doPublish = async body => {
    try {
      await apiCall('/api/cards', {
        method: 'POST',
        body: JSON.stringify({
          company: review.position?.company || '',
          position_title: review.position?.position_title || '',
          card_body: body,
          card_mode: shareMode,
          publish: true
        })
      });
      toast('已发布到面经墙 ✨', 'success');
      setShareMode(null);
      setSharePreview('');
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  if (error) {
    return /*#__PURE__*/React.createElement(Modal, {
      open: true,
      onClose: onClose,
      title: "\u590D\u76D8\u5206\u6790",
      maxWidth: "max-w-2xl"
    }, /*#__PURE__*/React.createElement("div", {
      className: "text-sm text-red-500 py-4 text-center"
    }, "\u52A0\u8F7D\u5931\u8D25\uFF0C\u8BF7\u91CD\u8BD5"));
  }
  if (!review) {
    return /*#__PURE__*/React.createElement(Modal, {
      open: true,
      onClose: onClose,
      title: "\u590D\u76D8\u5206\u6790",
      maxWidth: "max-w-2xl"
    }, /*#__PURE__*/React.createElement("div", {
      className: "text-sm text-gray-400 py-4 text-center"
    }, "\u52A0\u8F7D\u4E2D..."));
  }
  const parsed = review.parsed;
  const insights = review.insights;
  return /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: onClose,
    title: "\u590D\u76D8\u5206\u6790",
    maxWidth: "max-w-3xl"
  }, /*#__PURE__*/React.createElement("div", {
    className: "space-y-5 text-sm"
  }, parsed?.overall_self_rating != null && /*#__PURE__*/React.createElement("div", {
    className: "p-3 rounded-lg bg-brand-50 flex items-center gap-3 flex-wrap"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-2xl font-bold text-brand-700"
  }, parsed.overall_self_rating), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-brand-700"
  }, "/10 \u603B\u4F53\u81EA\u8BC4"), parsed.interviewer_style && /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-600 ml-auto"
  }, "\u9762\u8BD5\u5B98\u98CE\u683C\uFF1A", parsed.interviewer_style)), insights?.key_findings?.length > 0 && /*#__PURE__*/React.createElement(Section, {
    title: "\uD83C\uDFAF \u5173\u952E\u89C2\u5BDF"
  }, /*#__PURE__*/React.createElement("ul", {
    className: "text-xs text-gray-700 ml-4 list-disc space-y-1"
  }, insights.key_findings.map((f, i) => /*#__PURE__*/React.createElement("li", {
    key: i
  }, f)))), insights?.patterns_vs_history && /*#__PURE__*/React.createElement(Section, {
    title: "\uD83D\uDD01 \u8DE8\u6B21\u6A21\u5F0F"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-700 bg-amber-50 rounded p-3 border border-amber-100"
  }, insights.patterns_vs_history)), insights?.strengths?.length > 0 && /*#__PURE__*/React.createElement(Section, {
    title: "\u2713 \u505A\u5F97\u597D\u7684\u5730\u65B9"
  }, /*#__PURE__*/React.createElement("ul", {
    className: "text-xs text-gray-700 ml-4 list-disc space-y-1"
  }, insights.strengths.map((s, i) => /*#__PURE__*/React.createElement("li", {
    key: i
  }, s)))), insights?.weaknesses?.length > 0 && /*#__PURE__*/React.createElement(Section, {
    title: "\u2717 \u66B4\u9732\u7684\u77ED\u677F"
  }, /*#__PURE__*/React.createElement("ul", {
    className: "text-xs text-gray-700 ml-4 list-disc space-y-1"
  }, insights.weaknesses.map((s, i) => /*#__PURE__*/React.createElement("li", {
    key: i
  }, s)))), insights?.next_actions?.length > 0 && /*#__PURE__*/React.createElement(Section, {
    title: "\uD83D\uDCA1 \u4E0B\u4E00\u6B65\u6539\u8FDB"
  }, /*#__PURE__*/React.createElement("ul", {
    className: "text-xs text-gray-700 ml-4 list-disc space-y-1"
  }, insights.next_actions.map((s, i) => /*#__PURE__*/React.createElement("li", {
    key: i
  }, s)))), parsed?.qa_pairs?.length > 0 && /*#__PURE__*/React.createElement(Section, {
    title: "📋 问答回顾（" + parsed.qa_pairs.length + " 题）"
  }, /*#__PURE__*/React.createElement("div", {
    className: "space-y-3"
  }, parsed.qa_pairs.map((qa, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    className: "border-l-2 border-brand-300 pl-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-xs font-medium text-gray-900"
  }, "Q", i + 1, ": ", qa.question), qa.category && /*#__PURE__*/React.createElement("div", {
    className: "text-[10px] text-gray-400 mt-0.5"
  }, "\u5206\u7C7B\uFF1A", qa.category), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-600 mt-1"
  }, "A: ", qa.user_answer))))), /*#__PURE__*/React.createElement("div", {
    className: "pt-3 border-t border-gray-100"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-[10px] text-gray-400 mb-2 text-center"
  }, "\uD83D\uDCAB \u5206\u4EAB\u5230\u9762\u7ECF\u5899\uFF0C\u6512\u4EBA\u54C1 +1"), /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-2 gap-2"
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => doShareGenerate('qa'),
    className: "p-2.5 rounded-lg border border-gray-200 text-xs text-left hover:border-brand-300 hover:bg-brand-50 transition"
  }, /*#__PURE__*/React.createElement("span", {
    className: "font-semibold block mb-0.5"
  }, "\uD83D\uDCDD \u5B8C\u6574\u95EE\u7B54\u7248"), /*#__PURE__*/React.createElement("span", {
    className: "text-[10px] text-gray-400"
  }, "\u8131\u654F\u540E\u7684\u95EE\u7B54\u5168\u6587\uFF0CAI \u5E2E\u4F60\u6DA6\u8272")), /*#__PURE__*/React.createElement("button", {
    onClick: () => doShareGenerate('q_only'),
    className: "p-2.5 rounded-lg border border-gray-200 text-xs text-left hover:border-brand-300 hover:bg-brand-50 transition"
  }, /*#__PURE__*/React.createElement("span", {
    className: "font-semibold block mb-0.5"
  }, "\uD83C\uDFAF \u95EE\u9898\u901F\u89C8\u7248"), /*#__PURE__*/React.createElement("span", {
    className: "text-[10px] text-gray-400"
  }, "\u53EA\u5C55\u793A\u9762\u8BD5\u5173\u952E\u95EE\u9898")))))), shareMode && !shareLoading && sharePreview && /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: () => {
      setShareMode(null);
      setSharePreview('');
    },
    title: "\u9884\u89C8\u9762\u7ECF\u5361",
    maxWidth: "max-w-xl"
  }, /*#__PURE__*/React.createElement("div", {
    className: "space-y-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "bg-gray-50 rounded-xl p-4"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-500 mb-2"
  }, "AI \u5DF2\u751F\u6210\uFF0C\u4F60\u53EF\u4EE5\u7F16\u8F91\u540E\u518D\u53D1\u5E03"), /*#__PURE__*/React.createElement("textarea", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-200 text-sm leading-relaxed",
    rows: 10,
    value: sharePreview,
    onChange: e => setSharePreview(e.target.value)
  })), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 justify-end"
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "secondary",
    onClick: () => {
      setShareMode(null);
      setSharePreview('');
    }
  }, "\u53D6\u6D88"), /*#__PURE__*/React.createElement(Button, {
    variant: "primary",
    onClick: () => doPublish(sharePreview)
  }, "\u53D1\u5E03\u5230\u9762\u7ECF\u5899 \u2728")))), shareLoading && /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: () => {}
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-sm text-gray-400 py-4 text-center"
  }, "AI \u6B63\u5728\u751F\u6210\u9762\u7ECF\u5361\u7247...")));
}

// ==================== 画像池 ====================
const LAYER_META = {
  stable: {
    label: '稳定事实',
    desc: '几乎不变的身份/教育信息',
    color: 'bg-brand-50 border-brand-200 text-brand-700'
  },
  skill: {
    label: '技能标签',
    desc: '半年级别，从简历/项目里抽',
    color: 'bg-emerald-50 border-emerald-200 text-emerald-700'
  },
  behavior: {
    label: '行为画像',
    desc: '月级别，从偏好/经历里推断',
    color: 'bg-purple-50 border-purple-200 text-purple-700'
  },
  dynamic: {
    label: '临时洞察',
    desc: '周级别，候选或待验证',
    color: 'bg-amber-50 border-amber-200 text-amber-700'
  }
};
function ProfilePage() {
  const {
    toast
  } = useApp();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [auditing, setAuditing] = useState(false);
  const load = async () => {
    try {
      const r = await apiCall('/api/profile');
      setData(r);
    } catch (e) {
      toast(e.message, 'error');
    }
    setLoading(false);
  };
  useEffect(() => {
    load();
  }, []);
  const runAudit = async () => {
    if (!confirm('画像自审会调用 1 次深度 AI（约 20 秒）检查画像矛盾和陈旧标签，确定继续吗？')) return;
    setAuditing(true);
    try {
      const r = await apiCall('/api/profile/audit', {
        method: 'POST'
      });
      const msg = `自审完成 · 归档 ${r.tags_archived} 条陈旧 · 发现 ${r.conflicts?.length || 0} 处可疑`;
      toast(msg, 'success', 5000);
      load();
    } catch (e) {
      handleApiError(e, toast);
    }
    setAuditing(false);
  };
  const rejectTag = async id => {
    if (!confirm('把这条画像标签删除？（后续不再引用）')) return;
    try {
      await apiCall('/api/profile/tags/' + id, {
        method: 'DELETE'
      });
      toast('已删除', 'success');
      load();
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  if (loading) return /*#__PURE__*/React.createElement(Card, {
    className: "p-8 text-center text-gray-400 text-sm"
  }, "\u52A0\u8F7D\u4E2D...");
  const layers = data?.layers || {
    stable: [],
    skill: [],
    behavior: [],
    dynamic: []
  };
  const total = data?.total || 0;
  return /*#__PURE__*/React.createElement("div", {
    className: "animate-slide-up space-y-5"
  }, /*#__PURE__*/React.createElement(PageHeader, {
    title: "\u6211\u7684\u753B\u50CF",
    desc: total + ' 条活跃标签 · AI 基于简历/JD/复盘累积学习',
    action: /*#__PURE__*/React.createElement(Button, {
      variant: "secondary",
      onClick: runAudit,
      disabled: auditing
    }, auditing ? '自审中...' : '🔍 画像自审')
  }), total === 0 ? /*#__PURE__*/React.createElement("div", {
    className: "space-y-4 animate-page-enter"
  }, /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-1 md:grid-cols-3 gap-4"
  }, /*#__PURE__*/React.createElement("div", {
    className: "bg-white rounded-xl border border-gray-200 p-5 text-center shadow-soft stagger-cards"
  }, /*#__PURE__*/React.createElement("div", {
    className: "w-10 h-10 rounded-full bg-brand-50 text-brand-600 flex items-center justify-center mx-auto mb-3 text-lg font-bold"
  }, "1"), /*#__PURE__*/React.createElement("div", {
    className: "text-sm font-semibold text-gray-900 mb-1"
  }, "\u7C98\u8D34\u7B80\u5386"), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-500 leading-relaxed"
  }, "AI \u4ECE\u4F60\u7684\u5B66\u5386\u3001\u6280\u80FD\u3001\u9879\u76EE\u7ECF\u5386\u4E2D\u63D0\u53D6\u521D\u59CB\u6807\u7B7E\uFF0C\u5EFA\u7ACB\u753B\u50CF\u5730\u57FA\u3002")), /*#__PURE__*/React.createElement("div", {
    className: "bg-white rounded-xl border border-gray-200 p-5 text-center shadow-soft stagger-cards"
  }, /*#__PURE__*/React.createElement("div", {
    className: "w-10 h-10 rounded-full bg-emerald-50 text-emerald-600 flex items-center justify-center mx-auto mb-3 text-lg font-bold"
  }, "2"), /*#__PURE__*/React.createElement("div", {
    className: "text-sm font-semibold text-gray-900 mb-1"
  }, "\u7C98\u8D34\u76EE\u6807 JD"), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-500 leading-relaxed"
  }, "AI \u5206\u6790\u4F60\u504F\u597D\u7684\u5C97\u4F4D\u65B9\u5411\u548C\u6280\u80FD\u8981\u6C42\uFF0C\u8865\u5145\u6C42\u804C\u503E\u5411\u6807\u7B7E\u3002")), /*#__PURE__*/React.createElement("div", {
    className: "bg-white rounded-xl border border-gray-200 p-5 text-center shadow-soft stagger-cards"
  }, /*#__PURE__*/React.createElement("div", {
    className: "w-10 h-10 rounded-full bg-purple-50 text-purple-600 flex items-center justify-center mx-auto mb-3 text-lg font-bold"
  }, "3"), /*#__PURE__*/React.createElement("div", {
    className: "text-sm font-semibold text-gray-900 mb-1"
  }, "\u5B8C\u6210\u4E00\u6B21\u590D\u76D8"), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-500 leading-relaxed"
  }, "AI \u4ECE\u4F60\u7684\u9762\u8BD5\u8868\u73B0\u63A8\u65AD\u884C\u4E3A\u7279\u8D28\u548C\u8584\u5F31\u70B9\uFF0C\u753B\u50CF\u5F00\u59CB\u771F\u6B63\"\u8BA4\u8BC6\"\u4F60\u3002"))), /*#__PURE__*/React.createElement("div", {
    className: "text-center text-xs text-gray-400"
  }, "\u6BCF\u6B21\u4F7F\u7528\u90FD\u4F1A\u8BA9 AI \u66F4\u61C2\u4F60\uFF0C", /*#__PURE__*/React.createElement("span", {
    className: "text-brand-600 cursor-pointer hover:underline",
    onClick: () => navigate('resumes')
  }, "\u4ECE\u7C98\u8D34\u7B80\u5386\u5F00\u59CB \u2192"))) : /*#__PURE__*/React.createElement("div", {
    className: "space-y-5"
  }, Object.entries(LAYER_META).map(([key, meta]) => {
    const tags = layers[key] || [];
    if (tags.length === 0) return null;
    return /*#__PURE__*/React.createElement(Card, {
      key: key,
      className: "p-5"
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex items-center justify-between mb-3 flex-wrap gap-2"
    }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h3", {
      className: "font-semibold text-gray-900 flex items-center gap-2"
    }, /*#__PURE__*/React.createElement("span", {
      className: 'inline-block w-2 h-2 rounded-full ' + (key === 'stable' ? 'bg-brand-500' : key === 'skill' ? 'bg-emerald-500' : key === 'behavior' ? 'bg-purple-500' : 'bg-amber-500')
    }), meta.label, /*#__PURE__*/React.createElement("span", {
      className: "text-xs font-normal text-gray-400"
    }, "\xB7 ", tags.length)), /*#__PURE__*/React.createElement("div", {
      className: "text-xs text-gray-500 mt-0.5"
    }, meta.desc))), /*#__PURE__*/React.createElement("div", {
      className: "space-y-2"
    }, tags.map(t => /*#__PURE__*/React.createElement(ProfileTagCard, {
      key: t.id,
      tag: t,
      onReject: () => rejectTag(t.id)
    }))));
  }), data?.last_audit && (() => {
    let report = null;
    try {
      report = JSON.parse(data.last_audit.report || '{}');
    } catch (_) {}
    const conflicts = report?.conflicts || [];
    // 把 tag_keys 映射回完整 tag（方便点删）
    const allTags = [].concat(layers.stable || [], layers.skill || [], layers.behavior || [], layers.dynamic || []);
    const findTag = k => allTags.find(t => t.key === k);
    return /*#__PURE__*/React.createElement(Card, {
      className: "p-5 bg-amber-50/40 border-amber-200/60"
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex items-start justify-between flex-wrap gap-2 mb-3"
    }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h3", {
      className: "font-semibold text-gray-900 flex items-center gap-2"
    }, "\uD83D\uDD0E \u753B\u50CF\u81EA\u5BA1\u62A5\u544A"), /*#__PURE__*/React.createElement("div", {
      className: "text-xs text-gray-500 mt-1"
    }, new Date(data.last_audit.created_at).toLocaleString('zh-CN'), "\xB7 \u5F52\u6863\u9648\u65E7\u6807\u7B7E ", /*#__PURE__*/React.createElement("b", null, data.last_audit.tags_archived), " \u6761 \xB7 \u53D1\u73B0\u53EF\u7591 ", /*#__PURE__*/React.createElement("b", {
      className: "text-amber-700"
    }, data.last_audit.conflicts_found), " \u5904"))), conflicts.length === 0 ? /*#__PURE__*/React.createElement("div", {
      className: "text-sm text-gray-500"
    }, "\u2728 AI \u6CA1\u53D1\u73B0\u660E\u663E\u77DB\u76FE\uFF0C\u753B\u50CF\u5065\u5EB7") : /*#__PURE__*/React.createElement("div", {
      className: "space-y-3"
    }, /*#__PURE__*/React.createElement("div", {
      className: "text-xs text-gray-600 leading-relaxed bg-white/60 rounded p-2.5 border border-amber-100"
    }, "\uD83D\uDCA1 ", /*#__PURE__*/React.createElement("b", null, "\u600E\u4E48\u5904\u7406\u7591\u70B9\uFF1F"), "\u770B AI \u6307\u51FA\u7684\u539F\u56E0\u548C\u5EFA\u8BAE\uFF0C\u5982\u679C\u4F60\u8BA4\u4E3A AI \u8BF4\u5F97\u5BF9 \u2192 \u70B9\u4E0B\u65B9\u6D89\u53CA\u6807\u7B7E\u53F3\u4FA7\u7684\"\u5220\u9664\"\u6309\u94AE\u79FB\u9664\u9519\u7684\u90A3\u6761\uFF1B\u5982\u679C AI \u5224\u65AD\u9519\u4E86 \u2192 \u4E0D\u7528\u7BA1\u5B83\uFF0C\u4E0B\u6B21\u81EA\u5BA1\u5982\u679C\u8FD8\u5728\u53EF\u4EE5\u5FFD\u7565\u3002"), conflicts.map((c, idx) => /*#__PURE__*/React.createElement("div", {
      key: idx,
      className: "rounded-lg bg-white border border-amber-200 p-3.5"
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex items-start gap-2 mb-2"
    }, /*#__PURE__*/React.createElement("span", {
      className: "text-amber-500 text-sm"
    }, "\u26A0\uFE0F"), /*#__PURE__*/React.createElement("div", {
      className: "flex-1"
    }, /*#__PURE__*/React.createElement("div", {
      className: "text-sm text-gray-900 font-medium"
    }, "\u7591\u70B9 ", idx + 1, "\uFF1A", c.reason || '（未给出原因）'), c.suggestion && /*#__PURE__*/React.createElement("div", {
      className: "text-xs text-gray-600 mt-1 leading-relaxed"
    }, /*#__PURE__*/React.createElement("b", {
      className: "text-brand-600"
    }, "AI \u5EFA\u8BAE\uFF1A"), c.suggestion))), c.tag_keys && c.tag_keys.length > 0 && /*#__PURE__*/React.createElement("div", {
      className: "mt-2 pt-2 border-t border-gray-100 space-y-1.5"
    }, /*#__PURE__*/React.createElement("div", {
      className: "text-[11px] text-gray-400"
    }, "\u6D89\u53CA\u6807\u7B7E\uFF08\u70B9\u53F3\u4FA7\u5220\u9664\u53EF\u4E00\u952E\u79FB\u9664\uFF09\uFF1A"), c.tag_keys.map((k, i) => {
      const t = findTag(k);
      return /*#__PURE__*/React.createElement("div", {
        key: i,
        className: "flex items-center justify-between gap-2 text-xs bg-gray-50 rounded px-2.5 py-1.5"
      }, /*#__PURE__*/React.createElement("div", {
        className: "flex-1 min-w-0"
      }, /*#__PURE__*/React.createElement("span", {
        className: "font-medium text-gray-800"
      }, k), t?.value && /*#__PURE__*/React.createElement("span", {
        className: "text-gray-500"
      }, " \xB7 ", t.value), t ? /*#__PURE__*/React.createElement("span", {
        className: "ml-2 text-[10px] text-gray-400"
      }, "[", LAYER_META[t.layer]?.label || t.layer, " \xB7 \u7F6E\u4FE1\u5EA6 ", Math.round((t.confidence || 0) * 100), "%]") : /*#__PURE__*/React.createElement("span", {
        className: "ml-2 text-[10px] text-gray-400"
      }, "[\u6807\u7B7E\u53EF\u80FD\u5DF2\u88AB\u5220\u9664]")), t && /*#__PURE__*/React.createElement("button", {
        onClick: () => rejectTag(t.id),
        className: "text-rose-600 hover:bg-rose-50 px-2 py-0.5 rounded text-[11px] font-medium shrink-0"
      }, "\u5220\u9664\u8FD9\u6761"));
    }))))));
  })()));
}
function ProfileTagCard({
  tag,
  onReject
}) {
  const [expanded, setExpanded] = useState(false);
  const confPercent = Math.round((tag.confidence || 0) * 100);
  return /*#__PURE__*/React.createElement("div", {
    className: "rounded-lg border border-gray-100 hover:border-gray-200 transition p-3 animate-tag-pop"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex-1 min-w-0"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-2 flex-wrap"
  }, /*#__PURE__*/React.createElement("span", {
    className: "font-medium text-sm text-gray-900"
  }, tag.key), tag.value && /*#__PURE__*/React.createElement("span", {
    className: "text-xs text-gray-500"
  }, "\xB7 ", tag.value), /*#__PURE__*/React.createElement("span", {
    className: "text-[10px] text-gray-400"
  }, "\u7F6E\u4FE1\u5EA6", /*#__PURE__*/React.createElement("span", {
    className: 'ml-0.5 font-semibold ' + (confPercent >= 80 ? 'text-emerald-600' : confPercent >= 60 ? 'text-brand-600' : 'text-gray-500')
  }, confPercent, "%"))), /*#__PURE__*/React.createElement("div", {
    className: "text-[10px] text-gray-400 mt-0.5"
  }, tag.category, " \xB7 \u66F4\u65B0\u4E8E ", relTime(tag.last_updated_at), tag.evidences?.length > 0 && /*#__PURE__*/React.createElement(React.Fragment, null, " \xB7 ", tag.evidences.length, " \u6761\u8BC1\u636E"))), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-1"
  }, tag.evidences?.length > 0 && /*#__PURE__*/React.createElement("button", {
    onClick: () => setExpanded(!expanded),
    className: "text-xs text-gray-500 hover:text-gray-900 px-2 py-1 rounded hover:bg-gray-100 transition"
  }, expanded ? '收起' : '证据 →'), /*#__PURE__*/React.createElement("button", {
    onClick: onReject,
    className: "text-xs text-gray-400 hover:text-rose-600 px-2 py-1 rounded hover:bg-rose-50 transition",
    title: "\u5220\u9664"
  }, /*#__PURE__*/React.createElement(Icon.X, {
    className: "w-3.5 h-3.5"
  })))), expanded && tag.evidences?.length > 0 && /*#__PURE__*/React.createElement("div", {
    className: "mt-2 pt-2 border-t border-gray-100 space-y-1"
  }, tag.evidences.map(ev => /*#__PURE__*/React.createElement("div", {
    key: ev.id,
    className: "text-xs text-gray-600 pl-2 border-l-2 border-gray-200"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-[10px] text-gray-400 mr-1"
  }, "[", ev.source_type, "]"), "\"", ev.quote, "\""))));
}

// ==================== 陪练题 ====================
function PracticePage() {
  const {
    toast
  } = useApp();
  const [list, setList] = useState([]);
  const [positions, setPositions] = useState([]);
  const [filterPos, setFilterPos] = useState('');
  const [loading, setLoading] = useState(true);
  const [genModal, setGenModal] = useState(false);
  const [pasteModal, setPasteModal] = useState(false);
  const load = async () => {
    try {
      const url = '/api/practice' + (filterPos ? '?position_id=' + filterPos : '');
      const r = await apiCall(url);
      setList(r.questions || []);
    } catch (e) {
      toast(e.message, 'error');
    }
    setLoading(false);
  };
  const loadPositions = async () => {
    try {
      const r = await apiCall('/api/positions');
      setPositions(r.positions || []);
    } catch {}
  };
  useEffect(() => {
    load();
    loadPositions();
  }, []);
  useEffect(() => {
    load();
  }, [filterPos]);
  const del = async id => {
    if (!confirm('删除这道题？')) return;
    try {
      await apiCall('/api/practice/' + id, {
        method: 'DELETE'
      });
      toast('已删除', 'success');
      load();
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  const sourceLabel = s => ({
    llm_resume_dig: '🎯 简历深挖',
    web_search: '🔎 全网面经',
    user_pasted: '✏️ 粘贴'
  })[s] || s;
  return /*#__PURE__*/React.createElement("div", {
    className: "animate-slide-up"
  }, /*#__PURE__*/React.createElement(PageHeader, {
    title: "\u966A\u7EC3\u9898",
    desc: "AI \u7B80\u5386\u6DF1\u6316 + \u5168\u7F51\u771F\u5B9E\u9762\u7ECF\u641C\u7D22 + \u4F60\u7C98\u8D34\u7684\u9898\u76EE",
    action: /*#__PURE__*/React.createElement("div", {
      className: "flex gap-2"
    }, /*#__PURE__*/React.createElement(Button, {
      variant: "secondary",
      onClick: () => setPasteModal(true)
    }, "\u7C98\u8D34\u9898\u76EE"), /*#__PURE__*/React.createElement(Button, {
      variant: "primary",
      onClick: () => setGenModal(true)
    }, /*#__PURE__*/React.createElement(Icon.Plus, {
      className: "w-4 h-4 mr-1"
    }), " AI \u751F\u6210"))
  }), positions.length > 0 && /*#__PURE__*/React.createElement("div", {
    className: "mb-4"
  }, /*#__PURE__*/React.createElement("select", {
    className: "max-w-xs px-3 py-2 rounded-lg border border-gray-300 text-sm bg-white",
    value: filterPos,
    onChange: e => setFilterPos(e.target.value)
  }, /*#__PURE__*/React.createElement("option", {
    value: ""
  }, "\u5168\u90E8\u5C97\u4F4D"), positions.map(p => /*#__PURE__*/React.createElement("option", {
    key: p.id,
    value: p.id
  }, p.company, " \xB7 ", p.position_title)))), loading ? /*#__PURE__*/React.createElement(Card, {
    className: "p-8 text-center text-gray-400 text-sm"
  }, "\u52A0\u8F7D\u4E2D...") : list.length === 0 ? /*#__PURE__*/React.createElement(Card, {
    className: "p-0"
  }, /*#__PURE__*/React.createElement(EmptyState, {
    icon: "\uD83C\uDF93",
    title: "\u8FD8\u6CA1\u6709\u966A\u7EC3\u9898",
    desc: "AI \u53EF\u4EE5\u57FA\u4E8E\u4F60\u7684\u7B80\u5386\u548C\u76EE\u6807\u5C97\u4F4D\u751F\u6210\u6DF1\u6316\u9898 + \u4ECE\u7F51\u4E0A\u641C\u771F\u5B9E\u9762\u7ECF",
    action: /*#__PURE__*/React.createElement(Button, {
      variant: "primary",
      onClick: () => setGenModal(true)
    }, "\u751F\u6210\u7B2C\u4E00\u6279")
  })) : /*#__PURE__*/React.createElement("div", {
    className: "space-y-2"
  }, list.map(q => {
    const detail = q.source_detail ? typeof q.source_detail === 'string' ? JSON.parse(q.source_detail) : q.source_detail : null;
    return /*#__PURE__*/React.createElement(PracticeCard, {
      key: q.id,
      q: q,
      detail: detail,
      sourceLabel: sourceLabel,
      onDel: () => del(q.id)
    });
  })), genModal && /*#__PURE__*/React.createElement(GeneratePracticeModal, {
    positions: positions,
    onClose: () => setGenModal(false),
    onDone: () => {
      setGenModal(false);
      load();
    }
  }), pasteModal && /*#__PURE__*/React.createElement(PastePracticeModal, {
    positions: positions,
    onClose: () => setPasteModal(false),
    onDone: () => {
      setPasteModal(false);
      load();
    }
  }));
}
function PracticeCard({
  q,
  detail,
  sourceLabel,
  onDel
}) {
  const [expanded, setExpanded] = useState(false);
  return /*#__PURE__*/React.createElement(Card, {
    className: "p-4"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-start gap-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex-1 min-w-0"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-2 flex-wrap mb-1"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-[10px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-600"
  }, sourceLabel(q.source)), detail?.category && /*#__PURE__*/React.createElement("span", {
    className: "text-[10px] px-1.5 py-0.5 rounded bg-brand-50 text-brand-700"
  }, detail.category), detail?.difficulty && /*#__PURE__*/React.createElement("span", {
    className: "text-[10px] text-gray-400"
  }, "\u96BE\u5EA6 ", detail.difficulty, "/5")), /*#__PURE__*/React.createElement("div", {
    className: "text-sm font-medium text-gray-900"
  }, q.question), expanded && /*#__PURE__*/React.createElement("div", {
    className: "mt-2 pt-2 border-t border-gray-100 space-y-2"
  }, q.reference_answer && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "text-[10px] text-gray-400 mb-0.5"
  }, "\u53C2\u8003\u7B54\u9898\u8981\u70B9"), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-700 leading-relaxed whitespace-pre-wrap"
  }, q.reference_answer)), q.user_note && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "text-[10px] text-gray-400 mb-0.5"
  }, "\u6211\u7684\u7B14\u8BB0"), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-700 leading-relaxed whitespace-pre-wrap"
  }, q.user_note)), detail?.source_url && /*#__PURE__*/React.createElement("a", {
    href: detail.source_url,
    target: "_blank",
    rel: "noopener noreferrer",
    className: "text-xs text-brand-600 hover:underline"
  }, "\uD83D\uDD17 \u6765\u6E90\u94FE\u63A5"))), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-1"
  }, /*#__PURE__*/React.createElement(Button, {
    size: "sm",
    variant: "ghost",
    onClick: () => setExpanded(!expanded)
  }, expanded ? '收起' : '展开'), /*#__PURE__*/React.createElement(Button, {
    size: "sm",
    variant: "ghost",
    onClick: onDel,
    className: "text-rose-600 hover:bg-rose-50"
  }, /*#__PURE__*/React.createElement(Icon.X, {
    className: "w-3.5 h-3.5"
  })))));
}
function GeneratePracticeModal({
  positions,
  onClose,
  onDone
}) {
  const {
    toast
  } = useApp();
  const [positionId, setPositionId] = useState(positions[0]?.id || '');
  const [count, setCount] = useState(8);
  const [sources, setSources] = useState({
    resume_dig: true,
    web_search: true
  });
  const [submitting, setSubmitting] = useState(false);
  const submit = async () => {
    if (!positionId) return toast('选择一个岗位', 'error');
    const srcArr = [];
    if (sources.resume_dig) srcArr.push('resume_dig');
    if (sources.web_search) srcArr.push('web_search');
    if (srcArr.length === 0) return toast('至少选一个来源', 'error');
    setSubmitting(true);
    try {
      const r = await apiCall('/api/practice/generate', {
        method: 'POST',
        body: JSON.stringify({
          position_id: positionId,
          count,
          sources: srcArr
        })
      });
      toast(`已生成 ${r.count} 道题`, 'success');
      onDone();
    } catch (e) {
      handleApiError(e, toast);
    }
    setSubmitting(false);
  };
  return /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: onClose,
    title: "AI \u751F\u6210\u966A\u7EC3\u9898"
  }, /*#__PURE__*/React.createElement("div", {
    className: "space-y-3"
  }, positions.length === 0 ? /*#__PURE__*/React.createElement("div", {
    className: "text-sm text-amber-700 bg-amber-50 border border-amber-200 rounded p-3"
  }, "\u9700\u8981\u5148\u5728\u5C97\u4F4D\u770B\u677F\u6DFB\u52A0\u4E00\u4E2A\u5C97\u4F4D\u624D\u80FD\u751F\u6210\u966A\u7EC3\u9898") : /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u76EE\u6807\u5C97\u4F4D"), /*#__PURE__*/React.createElement("select", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm bg-white",
    value: positionId,
    onChange: e => setPositionId(e.target.value)
  }, positions.map(p => /*#__PURE__*/React.createElement("option", {
    key: p.id,
    value: p.id
  }, p.company, " \xB7 ", p.position_title)))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u9898\u76EE\u6570\u91CF\uFF08", count, "\uFF09"), /*#__PURE__*/React.createElement("input", {
    type: "range",
    min: "3",
    max: "15",
    value: count,
    onChange: e => setCount(Number(e.target.value)),
    className: "w-full accent-brand-600"
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-2 block"
  }, "\u9898\u76EE\u6765\u6E90"), /*#__PURE__*/React.createElement("label", {
    className: "flex items-center gap-2 text-sm text-gray-700 mb-1 cursor-pointer"
  }, /*#__PURE__*/React.createElement("input", {
    type: "checkbox",
    checked: sources.resume_dig,
    onChange: e => setSources({
      ...sources,
      resume_dig: e.target.checked
    }),
    className: "w-4 h-4 rounded accent-brand-600"
  }), "\uD83C\uDFAF AI \u7B80\u5386\u6DF1\u6316\uFF08Flash \u914D\u989D\uFF0C\u6DF1\u6316\u7B80\u5386\u7EC6\u8282\uFF09"), /*#__PURE__*/React.createElement("label", {
    className: "flex items-center gap-2 text-sm text-gray-700 cursor-pointer"
  }, /*#__PURE__*/React.createElement("input", {
    type: "checkbox",
    checked: sources.web_search,
    onChange: e => setSources({
      ...sources,
      web_search: e.target.checked
    }),
    className: "w-4 h-4 rounded accent-brand-600"
  }), "\uD83D\uDD0E \u5168\u7F51\u771F\u5B9E\u9762\u7ECF\uFF08\u725B\u5BA2/\u5C0F\u7EA2\u4E66/\u77E5\u4E4E\u7B49\uFF0C\u7CBE\u51C6\u641C\u5C97\u4F4D\u540D+\u516C\u53F8\u540D\uFF09"))), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 justify-end"
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "secondary",
    onClick: onClose
  }, "\u53D6\u6D88"), /*#__PURE__*/React.createElement(Button, {
    variant: "primary",
    onClick: submit,
    disabled: submitting || positions.length === 0
  }, submitting ? 'AI 生成中（约 20 秒）...' : '开始生成'))));
}
function PastePracticeModal({
  positions,
  onClose,
  onDone
}) {
  const {
    toast
  } = useApp();
  const [positionId, setPositionId] = useState('');
  const [question, setQuestion] = useState('');
  const [referenceAnswer, setReferenceAnswer] = useState('');
  const [userNote, setUserNote] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const submit = async () => {
    if (question.trim().length < 5) return toast('题目太短', 'error');
    setSubmitting(true);
    try {
      await apiCall('/api/practice/user-paste', {
        method: 'POST',
        body: JSON.stringify({
          position_id: positionId || null,
          question,
          reference_answer: referenceAnswer || null,
          user_note: userNote || null
        })
      });
      toast('已保存', 'success');
      onDone();
    } catch (e) {
      toast(e.message, 'error');
    }
    setSubmitting(false);
  };
  return /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: onClose,
    title: "\u7C98\u8D34\u9762\u8BD5\u9898\uFF08\u4E2A\u4EBA\u9762\u7ECF\u5E93\uFF09",
    maxWidth: "max-w-2xl"
  }, /*#__PURE__*/React.createElement("div", {
    className: "space-y-3"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u5173\u8054\u5C97\u4F4D\uFF08\u9009\u586B\uFF09"), /*#__PURE__*/React.createElement("select", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm bg-white",
    value: positionId,
    onChange: e => setPositionId(e.target.value)
  }, /*#__PURE__*/React.createElement("option", {
    value: ""
  }, "\u4E0D\u5173\u8054\u7279\u5B9A\u5C97\u4F4D"), positions.map(p => /*#__PURE__*/React.createElement("option", {
    key: p.id,
    value: p.id
  }, p.company, " \xB7 ", p.position_title)))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u9898\u76EE"), /*#__PURE__*/React.createElement("textarea", {
    rows: 2,
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm",
    placeholder: "\u5982\uFF1A\u8BF7\u8BB2\u4E00\u4E2A\u4F60\u505A\u8FC7\u7684\u6700\u6709\u6311\u6218\u7684\u9879\u76EE...",
    value: question,
    onChange: e => setQuestion(e.target.value)
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u53C2\u8003\u7B54\u6848/\u8981\u70B9\uFF08\u9009\u586B\uFF09"), /*#__PURE__*/React.createElement("textarea", {
    rows: 4,
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm",
    value: referenceAnswer,
    onChange: e => setReferenceAnswer(e.target.value)
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u6211\u7684\u7B14\u8BB0\uFF08\u9009\u586B\uFF09"), /*#__PURE__*/React.createElement("textarea", {
    rows: 3,
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm",
    placeholder: "\u9762\u8BD5\u5B98\u8FFD\u95EE\u4E86\u4EC0\u4E48\u3001\u81EA\u5DF1\u56DE\u7B54\u7684\u601D\u8DEF\u3001\u54EA\u91CC\u7B54\u9519\u4E86...",
    value: userNote,
    onChange: e => setUserNote(e.target.value)
  })), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 justify-end"
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "secondary",
    onClick: onClose
  }, "\u53D6\u6D88"), /*#__PURE__*/React.createElement(Button, {
    variant: "primary",
    onClick: submit,
    disabled: submitting
  }, "\u4FDD\u5B58"))));
}

// ==================== 面经墙 v3.3 ====================
function WallPage() {
  const {
    toast,
    user
  } = useApp();
  const [cards, setCards] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [tagFilter, setTagFilter] = useState('');
  const [viewing, setViewing] = useState(null);
  const [showPublish, setShowPublish] = useState(false);
  const [bookmarks, setBookmarks] = useState(new Set());
  const loadWithTab = t => {
    setTab(t);
    setLoading(true);
    let url = '/api/cards';
    if (t === 'mine') url += '?mine=1';
    if (t === 'bookmark') url += '?bookmark=1';
    if (search) url += (url.includes('?') ? '&' : '?') + 'company=' + encodeURIComponent(search);
    if (tagFilter) url += (url.includes('?') ? '&' : '?') + 'tag=' + encodeURIComponent(tagFilter);
    apiCall(url).then(r => setCards(r.cards || [])).catch(e => toast(e.message, 'error')).finally(() => setLoading(false));
  };
  const load = () => loadWithTab(tab);
  useEffect(() => {
    load();
  }, []);
  const doBookmark = async cid => {
    try {
      const r = await apiCall('/api/likes', {
        method: 'POST',
        body: JSON.stringify({
          target_type: 'bookmark',
          target_id: cid
        })
      });
      setBookmarks(prev => {
        const next = new Set(prev);
        r.liked ? next.add(cid) : next.delete(cid);
        return next;
      });
    } catch {}
  };
  const relTime = ts => {
    if (!ts) return '';
    const diff = Date.now() - new Date(ts).getTime();
    const m = Math.floor(diff / 60000);
    if (m < 1) return '刚刚';
    if (m < 60) return m + '分钟前';
    const h = Math.floor(m / 60);
    if (h < 24) return h + '小时前';
    return Math.floor(h / 24) + '天前';
  };
  const tags = ['产品', '技术', '运营', '数据', '设计', '市场'];
  const [tab, setTab] = useState('all');
  return /*#__PURE__*/React.createElement("div", {
    className: "animate-slide-up"
  }, /*#__PURE__*/React.createElement(PageHeader, {
    title: "\u9762\u7ECF\u5899",
    desc: "\u5206\u4EAB\u771F\u5B9E\u9762\u8BD5\u7ECF\u9A8C\uFF0C\u5E2E\u5230\u522B\u4EBA\uFF0C\u4E5F\u6512\u81EA\u5DF1\u7684\u4EBA\u54C1\u6C60 \u2728",
    action: /*#__PURE__*/React.createElement(Button, {
      variant: "primary",
      onClick: () => setShowPublish(true)
    }, /*#__PURE__*/React.createElement(Icon.Plus, {
      className: "w-4 h-4 mr-1"
    }), " \u5206\u4EAB\u6211\u7684\u9762\u7ECF")
  }), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-1 mb-3"
  }, [{
    key: 'all',
    label: '全部'
  }, {
    key: 'mine',
    label: '我的发布'
  }, {
    key: 'bookmark',
    label: '⭐ 我的收藏'
  }].map(t => /*#__PURE__*/React.createElement("button", {
    key: t.key,
    onClick: () => loadWithTab(t.key),
    className: 'px-3 py-1.5 rounded-lg text-xs font-medium transition ' + (tab === t.key ? 'bg-brand-600 text-white' : 'bg-gray-100 text-gray-600 hover:bg-gray-200')
  }, t.label))), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 mb-4 flex-wrap"
  }, /*#__PURE__*/React.createElement("input", {
    className: "flex-1 min-w-[160px] px-3 py-2 rounded-lg border border-gray-300 text-sm",
    placeholder: "\u641C\u516C\u53F8\u540D...",
    value: search,
    onChange: e => setSearch(e.target.value),
    onKeyDown: e => e.key === 'Enter' && load()
  }), /*#__PURE__*/React.createElement(Button, {
    variant: "secondary",
    onClick: load
  }, "\u641C\u7D22"), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-1 flex-wrap"
  }, tags.map(t => /*#__PURE__*/React.createElement("button", {
    key: t,
    onClick: () => {
      setTagFilter(tagFilter === t ? '' : t);
    },
    className: 'px-2.5 py-1 rounded-lg text-xs font-medium transition ' + (tagFilter === t ? 'bg-brand-600 text-white' : 'bg-gray-100 text-gray-600 hover:bg-gray-200')
  }, "#", t)))), loading ? /*#__PURE__*/React.createElement(Card, {
    className: "p-8 text-center text-gray-400 text-sm"
  }, "\u52A0\u8F7D\u4E2D...") : cards.length === 0 ? /*#__PURE__*/React.createElement(Card, {
    className: "p-0"
  }, /*#__PURE__*/React.createElement(EmptyState, {
    icon: "\uD83D\uDEA9",
    title: "\u9762\u7ECF\u5899\u8FD8\u662F\u7A7A\u7684",
    desc: "\u5206\u4EAB\u4F60\u7684\u7B2C\u4E00\u4EFD\u9762\u8BD5\u7ECF\u9A8C\uFF0C\u6512\u4EBA\u54C1 +1",
    action: /*#__PURE__*/React.createElement(Button, {
      variant: "primary",
      onClick: () => setShowPublish(true)
    }, "\u5206\u4EAB\u9762\u7ECF")
  })) : /*#__PURE__*/React.createElement("div", {
    className: "space-y-3"
  }, cards.map(c => /*#__PURE__*/React.createElement(Card, {
    key: c.id,
    className: "p-4 clickable",
    onClick: () => setViewing(c.id)
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-start gap-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex-1 min-w-0"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-2 flex-wrap mb-1"
  }, /*#__PURE__*/React.createElement("span", {
    className: "font-semibold text-gray-900 text-sm"
  }, c.company), /*#__PURE__*/React.createElement("span", {
    className: "text-xs text-gray-500"
  }, "\xB7 ", c.position_title), c.score != null && /*#__PURE__*/React.createElement("span", {
    className: "text-[10px] px-1.5 py-0.5 rounded bg-brand-50 text-brand-700"
  }, c.score, "/10"), c.round_number && /*#__PURE__*/React.createElement("span", {
    className: "text-[10px] text-gray-400"
  }, "\u7B2C", c.round_number, "\u8F6E")), c.card_title && /*#__PURE__*/React.createElement("div", {
    className: "text-sm font-medium text-gray-800 mb-0.5"
  }, c.card_title), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-600 line-clamp-2 leading-relaxed"
  }, c.card_body.replace(/\n/g, ' ').slice(0, 200)), /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-3 mt-2 text-[10px] text-gray-400"
  }, /*#__PURE__*/React.createElement("span", null, c.author_display || c.author_name || '匿名'), /*#__PURE__*/React.createElement("span", null, relTime(c.created_at)), /*#__PURE__*/React.createElement("span", {
    className: "flex items-center gap-0.5"
  }, "\uD83D\uDC4D ", c.like_count || 0), /*#__PURE__*/React.createElement("span", {
    className: "flex items-center gap-0.5"
  }, "\uD83D\uDCAC ", c.question_count || 0))), /*#__PURE__*/React.createElement("div", {
    className: "flex flex-col items-end gap-1"
  }, /*#__PURE__*/React.createElement("button", {
    onClick: e => {
      e.stopPropagation();
      doBookmark(c.id);
    },
    className: "text-sm text-gray-300 hover:text-yellow-500 transition"
  }, bookmarks.has(c.id) ? '⭐' : '☆'), c.card_mode === 'q_only' && /*#__PURE__*/React.createElement("span", {
    className: "text-[10px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-500"
  }, "\u4EC5\u95EE\u9898")))))), viewing && /*#__PURE__*/React.createElement(WallCardDetail, {
    cardId: viewing,
    onClose: () => {
      setViewing(null);
      load();
    }
  }), showPublish && /*#__PURE__*/React.createElement(WallPublishModal, {
    onClose: () => setShowPublish(false),
    onDone: () => {
      setShowPublish(false);
      load();
    }
  }));
}
function WallCardDetail({
  cardId,
  onClose
}) {
  const {
    toast,
    user
  } = useApp();
  const [card, setCard] = useState(null);
  const [questions, setQuestions] = useState([]);
  const [aiQuestions, setAiQuestions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [customQ, setCustomQ] = useState('');
  const [replyText, setReplyText] = useState({});
  const loadCard = async () => {
    try {
      const r = await apiCall('/api/cards/' + cardId);
      setCard(r.card);
      const qr = await apiCall('/api/cards/' + cardId + '/questions');
      setQuestions(qr.questions || []);
    } catch (e) {
      toast(e.message, 'error');
    }
    setLoading(false);
  };
  const loadAI = async () => {
    try {
      const r = await apiCall('/api/cards/' + cardId + '/questions/generate', {
        method: 'POST'
      });
      setAiQuestions(r.questions || []);
    } catch {}
  };
  useEffect(() => {
    loadCard();
    loadAI();
  }, [cardId]);
  const doLike = async () => {
    try {
      const r = await apiCall('/api/likes', {
        method: 'POST',
        body: JSON.stringify({
          target_type: 'card',
          target_id: cardId
        })
      });
      setCard({
        ...card,
        is_liked: r.liked,
        like_count: (card.like_count || 0) + (r.liked ? 1 : -1)
      });
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  const doAsk = async text => {
    if (!text.trim()) return;
    try {
      await apiCall('/api/cards/' + cardId + '/questions', {
        method: 'POST',
        body: JSON.stringify({
          question_text: text,
          is_ai_generated: aiQuestions.includes(text)
        })
      });
      toast('已提问，等待卡主回复', 'success');
      loadCard();
      loadAI();
      setCustomQ('');
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  const doReply = async (qid, text) => {
    if (!text.trim()) return;
    try {
      await apiCall('/api/cards/' + cardId + '/questions/' + qid, {
        method: 'PUT',
        body: JSON.stringify({
          reply_text: text
        })
      });
      toast('已回复', 'success');
      loadCard();
      setReplyText({
        ...replyText,
        [qid]: ''
      });
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  const doLikeQ = async qid => {
    try {
      await apiCall('/api/likes', {
        method: 'POST',
        body: JSON.stringify({
          target_type: 'question',
          target_id: qid
        })
      });
      loadCard();
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  if (loading) return /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: onClose,
    title: "\u52A0\u8F7D\u4E2D..."
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-sm text-gray-400 py-4 text-center"
  }, "\u52A0\u8F7D\u4E2D..."));
  if (!card) return /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: onClose,
    title: "\u9762\u7ECF\u8BE6\u60C5"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-sm text-red-500 py-4 text-center"
  }, "\u52A0\u8F7D\u5931\u8D25"));
  const isOwner = user?.id === card.user_id;
  return /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: onClose,
    title: card.company + ' · ' + card.position_title,
    maxWidth: "max-w-2xl"
  }, /*#__PURE__*/React.createElement("div", {
    className: "space-y-4"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-3 text-xs text-gray-500"
  }, /*#__PURE__*/React.createElement("span", null, card.author_display || card.author_name || '匿名'), card.score != null && /*#__PURE__*/React.createElement("span", {
    className: "text-brand-700 font-semibold"
  }, card.score, "/10"), card.round_number && /*#__PURE__*/React.createElement("span", null, "\u7B2C", card.round_number, "\u8F6E", card.round_type ? ' · ' + card.round_type : '')), card.card_title && /*#__PURE__*/React.createElement("div", {
    className: "text-base font-semibold text-gray-900"
  }, card.card_title), /*#__PURE__*/React.createElement("div", {
    className: "text-sm text-gray-700 leading-relaxed whitespace-pre-wrap bg-gray-50 rounded-xl p-4"
  }, card.card_body), card.ai_tags && /*#__PURE__*/React.createElement("div", {
    className: "flex gap-1 flex-wrap"
  }, JSON.parse(card.ai_tags || '[]').map((t, i) => /*#__PURE__*/React.createElement("span", {
    key: i,
    className: "text-[10px] px-1.5 py-0.5 rounded bg-brand-50 text-brand-700"
  }, "#", t))), /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-3 pt-2 border-t border-gray-100"
  }, /*#__PURE__*/React.createElement("button", {
    onClick: doLike,
    className: 'flex items-center gap-1 text-xs px-3 py-1.5 rounded-lg transition ' + (card.is_liked ? 'bg-brand-50 text-brand-700' : 'bg-gray-100 text-gray-600 hover:bg-gray-200')
  }, "\uD83D\uDC4D ", card.like_count || 0), /*#__PURE__*/React.createElement("span", {
    className: "text-xs text-gray-400"
  }, "\uD83D\uDCAC ", card.question_count || 0, " \u4E2A\u8FFD\u95EE")), aiQuestions.length > 0 && /*#__PURE__*/React.createElement("div", {
    className: "space-y-2 pt-2 border-t border-gray-100"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-xs font-medium text-gray-500"
  }, "\uD83E\uDD16 AI \u63A8\u8350\u8FFD\u95EE"), /*#__PURE__*/React.createElement("div", {
    className: "space-y-1.5"
  }, aiQuestions.map((q, i) => {
    const asked = questions.some(qq => qq.question_text === q);
    return /*#__PURE__*/React.createElement("button", {
      key: i,
      disabled: asked,
      onClick: () => doAsk(q),
      className: 'w-full text-left px-3 py-2 rounded-lg text-xs transition ' + (asked ? 'bg-gray-50 text-gray-300 cursor-default' : 'bg-gray-50 text-gray-700 hover:bg-brand-50 hover:text-brand-700 border border-gray-100 hover:border-brand-200')
    }, asked ? '✅ ' : '', q);
  }))), questions.filter(q => !q.is_hidden).length > 0 && /*#__PURE__*/React.createElement("div", {
    className: "space-y-2 pt-2 border-t border-gray-100"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-xs font-medium text-gray-500"
  }, "\u95EE\u7B54"), questions.filter(q => !q.is_hidden).map(q => /*#__PURE__*/React.createElement("div", {
    key: q.id,
    className: "bg-gray-50 rounded-lg p-3 space-y-1.5"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-start justify-between gap-2"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-800"
  }, /*#__PURE__*/React.createElement("span", {
    className: "font-medium"
  }, q.asker_display || q.asker_name || '匿名'), /*#__PURE__*/React.createElement("span", {
    className: "text-gray-400 ml-1"
  }, "\u95EE\uFF1A"), q.question_text), /*#__PURE__*/React.createElement("button", {
    onClick: () => doLikeQ(q.id),
    className: "text-[10px] text-gray-400 hover:text-brand-600 flex-shrink-0"
  }, "\uD83D\uDC4D ", q.like_count || 0)), q.reply_text ? /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-brand-700 bg-brand-50 rounded px-2.5 py-1.5"
  }, /*#__PURE__*/React.createElement("span", {
    className: "font-medium"
  }, "\u5361\u4E3B\u56DE\u590D\uFF1A"), q.reply_text) : isOwner ? /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2"
  }, /*#__PURE__*/React.createElement("input", {
    className: "flex-1 px-2 py-1 rounded border border-gray-200 text-xs",
    placeholder: "\u8F93\u5165\u56DE\u590D...",
    value: replyText[q.id] || '',
    onChange: e => setReplyText({
      ...replyText,
      [q.id]: e.target.value
    }),
    onKeyDown: e => e.key === 'Enter' && doReply(q.id, replyText[q.id])
  }), /*#__PURE__*/React.createElement(Button, {
    size: "sm",
    variant: "primary",
    onClick: () => doReply(q.id, replyText[q.id])
  }, "\u56DE\u590D")) : /*#__PURE__*/React.createElement("div", {
    className: "text-[10px] text-gray-400 italic"
  }, "\u7B49\u5F85\u5361\u4E3B\u56DE\u590D...")))), /*#__PURE__*/React.createElement("div", {
    className: "pt-2 border-t border-gray-100"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2"
  }, /*#__PURE__*/React.createElement("input", {
    className: "flex-1 px-3 py-2 rounded-lg border border-gray-200 text-xs",
    placeholder: "\u81EA\u5DF1\u6709\u60F3\u95EE\u7684\uFF1F\u5728\u8FD9\u91CC\u63D0\uFF08\u5361\u4E3B\u56DE\u590D\u540E\u53EF\u89C1\uFF09...",
    value: customQ,
    onChange: e => setCustomQ(e.target.value),
    onKeyDown: e => e.key === 'Enter' && doAsk(customQ)
  }), /*#__PURE__*/React.createElement(Button, {
    size: "sm",
    variant: "secondary",
    onClick: () => doAsk(customQ)
  }, "\u63D0\u95EE")), /*#__PURE__*/React.createElement("div", {
    className: "text-[10px] text-gray-300 mt-1"
  }, "\u81EA\u5B9A\u4E49\u63D0\u95EE\u9ED8\u8BA4\u9690\u85CF\uFF0C\u5361\u4E3B\u56DE\u590D\u540E\u516C\u5F00\u53EF\u89C1"))));
}
function WallPublishModal({
  onClose,
  onDone
}) {
  const {
    toast
  } = useApp();
  const [mode, setMode] = useState('qa');
  const [company, setCompany] = useState('');
  const [positionTitle, setPositionTitle] = useState('');
  const [body, setBody] = useState('');
  const [title, setTitle] = useState('');
  const [tags, setTags] = useState([]);
  const [step, setStep] = useState(1);
  const [submitting, setSubmitting] = useState(false);
  const allTags = ['产品', '技术', '运营', '数据', '设计', '市场', '一面', '二面', '终面'];
  const doPublish = async () => {
    if (!company.trim()) return toast('请填写公司名', 'error');
    if (!body.trim() || body.trim().length < 20) return toast('内容太短', 'error');
    setSubmitting(true);
    try {
      await apiCall('/api/cards', {
        method: 'POST',
        body: JSON.stringify({
          company: company.trim(),
          position_title: positionTitle.trim() || '未填岗位',
          card_body: body.trim(),
          card_title: title.trim() || null,
          card_mode: mode,
          ai_tags: tags,
          publish: true
        })
      });
      toast('面经已发布 ✨', 'success');
      onDone();
    } catch (e) {
      toast(e.message, 'error');
    }
    setSubmitting(false);
  };
  if (step === 2) return /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: onClose,
    title: "\u9884\u89C8\u5E76\u53D1\u5E03",
    maxWidth: "max-w-xl"
  }, /*#__PURE__*/React.createElement("div", {
    className: "space-y-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "bg-gray-50 rounded-xl p-4"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-2 mb-2"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-sm font-semibold text-gray-900"
  }, company || '未填公司'), positionTitle && /*#__PURE__*/React.createElement("span", {
    className: "text-xs text-gray-500"
  }, "\xB7 ", positionTitle), /*#__PURE__*/React.createElement("span", {
    className: "text-[10px] px-1.5 py-0.5 rounded bg-yellow-100 text-yellow-700"
  }, mode === 'qa' ? '完整问答' : '仅问题')), title && /*#__PURE__*/React.createElement("div", {
    className: "text-sm font-medium text-gray-800 mb-1"
  }, title), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-700 whitespace-pre-wrap leading-relaxed"
  }, body), tags.length > 0 && /*#__PURE__*/React.createElement("div", {
    className: "flex gap-1 mt-2 flex-wrap"
  }, tags.map(t => /*#__PURE__*/React.createElement("span", {
    key: t,
    className: "text-[10px] px-1.5 py-0.5 rounded bg-brand-50 text-brand-700"
  }, "#", t)))), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 justify-end"
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "secondary",
    onClick: () => setStep(1)
  }, "\u8FD4\u56DE\u4FEE\u6539"), /*#__PURE__*/React.createElement(Button, {
    variant: "primary",
    onClick: doPublish,
    disabled: submitting
  }, submitting ? '发布中...' : '确认发布 ✨'))));
  return /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: onClose,
    title: "\u5206\u4EAB\u9762\u7ECF \xB7 \u6512\u4EBA\u54C1 +1",
    maxWidth: "max-w-xl"
  }, /*#__PURE__*/React.createElement("div", {
    className: "space-y-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-2 gap-2"
  }, /*#__PURE__*/React.createElement("input", {
    className: "px-3 py-2 rounded-lg border border-gray-300 text-sm",
    placeholder: "\u516C\u53F8\u540D\uFF08\u5FC5\u586B\uFF09",
    value: company,
    onChange: e => setCompany(e.target.value)
  }), /*#__PURE__*/React.createElement("input", {
    className: "px-3 py-2 rounded-lg border border-gray-300 text-sm",
    placeholder: "\u5C97\u4F4D\u540D",
    value: positionTitle,
    onChange: e => setPositionTitle(e.target.value)
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u5206\u4EAB\u6A21\u5F0F"), /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-2 gap-2"
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => setMode('qa'),
    className: 'p-2.5 rounded-lg border text-xs text-left transition ' + (mode === 'qa' ? 'border-brand-400 bg-brand-50 text-brand-700' : 'border-gray-200 text-gray-600 hover:border-gray-300')
  }, /*#__PURE__*/React.createElement("span", {
    className: "font-semibold block mb-0.5"
  }, "\uD83D\uDCDD \u5B8C\u6574\u95EE\u7B54\u7248"), /*#__PURE__*/React.createElement("span", {
    className: "text-[10px] text-gray-400"
  }, "\u8131\u654F\u540E\u7684\u95EE\u7B54\u5168\u6587")), /*#__PURE__*/React.createElement("button", {
    onClick: () => setMode('q_only'),
    className: 'p-2.5 rounded-lg border text-xs text-left transition ' + (mode === 'q_only' ? 'border-brand-400 bg-brand-50 text-brand-700' : 'border-gray-200 text-gray-600 hover:border-gray-300')
  }, /*#__PURE__*/React.createElement("span", {
    className: "font-semibold block mb-0.5"
  }, "\uD83C\uDFAF \u95EE\u9898\u901F\u89C8\u7248"), /*#__PURE__*/React.createElement("span", {
    className: "text-[10px] text-gray-400"
  }, "\u53EA\u5C55\u793A\u9762\u8BD5\u95EE\u9898")))), /*#__PURE__*/React.createElement("input", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm",
    placeholder: "\u4E00\u53E5\u8BDD\u6807\u9898\uFF08\u9009\u586B\uFF0C\u5982\uFF1A\u5B57\u8282\u4E8C\u9762\u8E29\u5751\u8BB0\uFF09",
    value: title,
    onChange: e => setTitle(e.target.value)
  }), /*#__PURE__*/React.createElement("textarea", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm leading-relaxed",
    rows: 8,
    placeholder: mode === 'qa' ? '粘贴面试问答...\n\n面试官问：...\n我答：...' : '列出面试中被问到的关键问题...',
    value: body,
    onChange: e => setBody(e.target.value)
  }), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u6807\u7B7E\uFF08\u9009\u586B\uFF09"), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-1 flex-wrap"
  }, allTags.map(t => {
    const active = tags.includes(t);
    return /*#__PURE__*/React.createElement("button", {
      key: t,
      onClick: () => setTags(active ? tags.filter(x => x !== t) : [...tags, t]),
      className: 'px-2 py-0.5 rounded text-[10px] font-medium transition ' + (active ? 'bg-brand-600 text-white' : 'bg-gray-100 text-gray-500 hover:bg-gray-200')
    }, "#", t);
  }))), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 justify-end"
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "secondary",
    onClick: onClose
  }, "\u53D6\u6D88"), /*#__PURE__*/React.createElement(Button, {
    variant: "primary",
    onClick: () => setStep(2)
  }, "\u9884\u89C8"))));
}

// ==================== AI 建议 ====================
function SuggestionsPage() {
  const {
    toast
  } = useApp();
  const [list, setList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const load = async () => {
    try {
      const r = await apiCall('/api/suggestions');
      setList(r.suggestions || []);
    } catch (e) {
      toast(e.message, 'error');
    }
    setLoading(false);
  };
  useEffect(() => {
    load();
  }, []);
  const generate = async () => {
    if (!confirm('基于你的画像生成新的 AI 建议（消耗 1 次深度配额）？')) return;
    setGenerating(true);
    try {
      const r = await apiCall('/api/suggestions/generate', {
        method: 'POST'
      });
      toast(`已生成 ${r.count} 条建议`, 'success');
      load();
    } catch (e) {
      handleApiError(e, toast);
    }
    setGenerating(false);
  };
  const updateStatus = async (id, status) => {
    try {
      await apiCall('/api/suggestions/' + id, {
        method: 'PUT',
        body: JSON.stringify({
          status
        })
      });
      load();
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  const typeLabel = t => ({
    direction: '🧭 方向',
    skill_gap: '🛠️ 能力补齐',
    next_action: '👉 下一步'
  })[t] || t;
  const statusBadge = s => ({
    new: 'bg-brand-50 text-brand-700 border-brand-200',
    viewed: 'bg-gray-50 text-gray-600 border-gray-200',
    adopted: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    dismissed: 'bg-rose-50 text-rose-500 border-rose-200'
  })[s] || 'bg-gray-50 text-gray-600 border-gray-200';
  return /*#__PURE__*/React.createElement("div", {
    className: "animate-slide-up"
  }, /*#__PURE__*/React.createElement(PageHeader, {
    title: "AI \u5EFA\u8BAE",
    desc: "\u57FA\u4E8E\u753B\u50CF\u6C60 + \u8FD1\u671F\u5C97\u4F4D\u52A8\u6001\u751F\u6210\u7684\u4E2A\u6027\u5316\u884C\u52A8\u5EFA\u8BAE",
    action: /*#__PURE__*/React.createElement(Button, {
      variant: "primary",
      onClick: generate,
      disabled: generating
    }, generating ? '生成中...' : '🔮 生成新建议')
  }), loading ? /*#__PURE__*/React.createElement(Card, {
    className: "p-8 text-center text-gray-400 text-sm"
  }, "\u52A0\u8F7D\u4E2D...") : list.length === 0 ? /*#__PURE__*/React.createElement(Card, {
    className: "p-0"
  }, /*#__PURE__*/React.createElement(EmptyState, {
    icon: "\uD83D\uDCA1",
    title: "\u8FD8\u6CA1\u6709\u5EFA\u8BAE",
    desc: "AI \u9700\u8981\u4F60\u7684\u753B\u50CF\u6709\u4E00\u5B9A\u79EF\u7D2F\uFF08\u81F3\u5C11 3 \u6761\u6807\u7B7E\uFF09\u624D\u80FD\u7ED9\u51FA\u6709\u4EF7\u503C\u7684\u5EFA\u8BAE\u3002\u5148\u7C98\u8D34\u7B80\u5386\u548C\u51E0\u4EFD JD \u5427\u3002",
    action: /*#__PURE__*/React.createElement(Button, {
      variant: "primary",
      onClick: generate
    }, "\u751F\u6210\u8BD5\u8BD5")
  })) : /*#__PURE__*/React.createElement("div", {
    className: "space-y-3"
  }, list.map(s => {
    const basedOn = s.based_on ? typeof s.based_on === 'string' ? JSON.parse(s.based_on) : s.based_on : [];
    return /*#__PURE__*/React.createElement(Card, {
      key: s.id,
      className: "p-5"
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex items-start gap-3"
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex-1 min-w-0"
    }, /*#__PURE__*/React.createElement("div", {
      className: "flex items-center gap-2 flex-wrap mb-1"
    }, /*#__PURE__*/React.createElement("span", {
      className: "text-xs font-semibold text-gray-700"
    }, typeLabel(s.suggestion_type)), /*#__PURE__*/React.createElement("span", {
      className: 'text-[10px] px-1.5 py-0.5 rounded border ' + statusBadge(s.status)
    }, s.status === 'new' ? '未查看' : s.status === 'viewed' ? '已查看' : s.status === 'adopted' ? '已采纳' : '已忽略'), /*#__PURE__*/React.createElement("span", {
      className: "text-[10px] text-gray-400"
    }, relTime(s.created_at))), /*#__PURE__*/React.createElement("h3", {
      className: "font-semibold text-gray-900 mb-1"
    }, s.title), /*#__PURE__*/React.createElement("p", {
      className: "text-sm text-gray-700 leading-relaxed"
    }, s.content), basedOn.length > 0 && /*#__PURE__*/React.createElement("div", {
      className: "mt-2 flex flex-wrap gap-1"
    }, /*#__PURE__*/React.createElement("span", {
      className: "text-[10px] text-gray-400"
    }, "\u4F9D\u636E\uFF1A"), basedOn.map((b, i) => /*#__PURE__*/React.createElement("span", {
      key: i,
      className: "text-[10px] px-1.5 py-0.5 rounded bg-gray-50 text-gray-600 border border-gray-200"
    }, b))))), s.status !== 'adopted' && s.status !== 'dismissed' && /*#__PURE__*/React.createElement("div", {
      className: "mt-3 pt-3 border-t border-gray-100 flex gap-1 justify-end"
    }, /*#__PURE__*/React.createElement(Button, {
      size: "sm",
      variant: "ghost",
      onClick: () => updateStatus(s.id, 'dismissed'),
      className: "text-gray-500"
    }, "\u5FFD\u7565"), /*#__PURE__*/React.createElement(Button, {
      size: "sm",
      variant: "accent",
      onClick: () => updateStatus(s.id, 'adopted')
    }, "\u2713 \u91C7\u7EB3")));
  })));
}

// ==================== 复盘总览（独立 Tab） ====================
function ReviewsPage() {
  const {
    toast,
    navigate
  } = useApp();
  const [list, setList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [viewing, setViewing] = useState(null);
  const [pasteOpen, setPasteOpen] = useState(false);
  const load = async () => {
    try {
      const r = await apiCall('/api/reviews');
      setList(r.reviews || []);
    } catch (e) {
      toast(e.message, 'error');
    }
    setLoading(false);
  };
  useEffect(() => {
    load();
  }, []);
  const relTime = ts => {
    if (!ts) return '';
    const diff = Date.now() - new Date(ts).getTime();
    const m = Math.floor(diff / 60000);
    if (m < 1) return '刚刚';
    if (m < 60) return m + '分钟前';
    const h = Math.floor(m / 60);
    if (h < 24) return h + '小时前';
    return Math.floor(h / 24) + '天前';
  };
  const statusLabel = s => s === 'done' ? '✅ 已分析' : s === 'processing' ? '⏳ 分析中' : '⏳ 待分析';
  const stats = {
    total: list.length,
    done: list.filter(r => r.parse_status === 'done').length
  };
  return /*#__PURE__*/React.createElement("div", {
    className: "animate-slide-up"
  }, /*#__PURE__*/React.createElement(PageHeader, {
    title: "\u9762\u8BD5\u590D\u76D8",
    desc: stats.total === 0 ? '每次面试后粘贴复盘，AI 帮你分析表现' : `${stats.total} 次复盘 · ${stats.done} 次已分析`,
    action: /*#__PURE__*/React.createElement(Button, {
      variant: "primary",
      onClick: () => setPasteOpen(true)
    }, /*#__PURE__*/React.createElement(Icon.Plus, {
      className: "w-4 h-4 mr-1"
    }), "\u7C98\u8D34\u590D\u76D8")
  }), loading ? /*#__PURE__*/React.createElement(Card, {
    className: "p-8 text-center text-gray-400 text-sm"
  }, "\u52A0\u8F7D\u4E2D...") : list.length === 0 ? /*#__PURE__*/React.createElement(Card, {
    className: "p-0"
  }, /*#__PURE__*/React.createElement(EmptyState, {
    icon: "\uD83D\uDCDD",
    title: "\u8FD8\u6CA1\u6709\u590D\u76D8\u8BB0\u5F55",
    desc: "\u7C98\u8D34\u9762\u8BD5\u56DE\u5FC6\uFF0CAI \u5E2E\u4F60\u7ED3\u6784\u5316\u5206\u6790\u5E76\u5199\u5165\u4E2A\u4EBA\u753B\u50CF",
    action: /*#__PURE__*/React.createElement(Button, {
      variant: "primary",
      onClick: () => setPasteOpen(true)
    }, "\u7C98\u8D34\u7B2C\u4E00\u4EFD\u590D\u76D8")
  })) : /*#__PURE__*/React.createElement("div", {
    className: "space-y-2"
  }, list.map(r => /*#__PURE__*/React.createElement(Card, {
    key: r.id,
    className: "p-4 clickable",
    onClick: () => setViewing(r.id)
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-start gap-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex-1 min-w-0"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-2 flex-wrap mb-1"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-sm font-semibold text-gray-900"
  }, r.company || '—'), r.position_title && /*#__PURE__*/React.createElement("span", {
    className: "text-xs text-gray-500"
  }, "\xB7 ", r.position_title), /*#__PURE__*/React.createElement("span", {
    className: "text-[10px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-600"
  }, statusLabel(r.parse_status)), /*#__PURE__*/React.createElement("span", {
    className: "text-[10px] text-gray-400"
  }, relTime(r.created_at))), r.preview && /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-600 line-clamp-2 mt-1"
  }, r.preview)))))), viewing && /*#__PURE__*/React.createElement(ReviewViewer, {
    reviewId: viewing,
    onClose: () => {
      setViewing(null);
      load();
    }
  }), pasteOpen && /*#__PURE__*/React.createElement(ReviewPasteModal, {
    onClose: () => setPasteOpen(false),
    onDone: reviewId => {
      setPasteOpen(false);
      load();
      setViewing(reviewId);
    }
  }));
}

// 复盘粘贴弹窗（在复盘Tab直接打开）
function ReviewPasteModal({
  onClose,
  onDone
}) {
  const {
    toast
  } = useApp();
  const [positions, setPositions] = useState([]);
  const [positionId, setPositionId] = useState('');
  const [roundId, setRoundId] = useState('');
  const [rounds, setRounds] = useState([]);
  const [rawText, setRawText] = useState('');
  const [submitting, setSubmitting] = useState(false);
  useEffect(() => {
    apiCall('/api/positions').then(r => {
      setPositions(r.positions || []);
      if (r.positions?.length > 0) setPositionId(r.positions[0].id);
    }).catch(() => {});
  }, []);
  useEffect(() => {
    if (!positionId) return;
    apiCall('/api/positions/' + positionId + '/rounds').then(r => setRounds(r.rounds || [])).catch(() => {});
  }, [positionId]);
  const submit = async () => {
    if (!positionId) return toast('请选择岗位', 'error');
    if (rawText.trim().length < 30) return toast('复盘内容至少 30 字', 'error');
    setSubmitting(true);
    try {
      const r = await apiCall('/api/reviews', {
        method: 'POST',
        body: JSON.stringify({
          position_id: positionId,
          round_id: roundId || null,
          raw_text: rawText.trim()
        })
      });
      toast('AI 复盘分析完成', 'success');
      onDone(r.id || r.review?.id);
    } catch (e) {
      handleApiError(e, toast);
    }
    setSubmitting(false);
  };
  return /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: onClose,
    title: "\u7C98\u8D34\u590D\u76D8",
    maxWidth: "max-w-xl"
  }, /*#__PURE__*/React.createElement("div", {
    className: "space-y-3"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u5173\u8054\u5C97\u4F4D"), /*#__PURE__*/React.createElement("select", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm bg-white",
    value: positionId,
    onChange: e => setPositionId(e.target.value)
  }, positions.map(p => /*#__PURE__*/React.createElement("option", {
    key: p.id,
    value: p.id
  }, p.company, " \xB7 ", p.position_title)))), rounds.length > 0 && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u5173\u8054\u8F6E\u6B21\uFF08\u9009\u586B\uFF09"), /*#__PURE__*/React.createElement("select", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm bg-white",
    value: roundId,
    onChange: e => setRoundId(e.target.value)
  }, /*#__PURE__*/React.createElement("option", {
    value: ""
  }, "\u4E0D\u5173\u8054\u7279\u5B9A\u8F6E\u6B21"), rounds.map(r => /*#__PURE__*/React.createElement("option", {
    key: r.id,
    value: r.id
  }, "\u7B2C", r.round_number, "\u8F6E", r.round_type ? ' · ' + r.round_type : '')))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs font-medium text-gray-700 mb-1 block"
  }, "\u590D\u76D8\u5185\u5BB9"), /*#__PURE__*/React.createElement("textarea", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm leading-relaxed",
    rows: 8,
    placeholder: "\u7C98\u8D34\u9762\u8BD5\u7684\u5B8C\u6574\u56DE\u5FC6\uFF0C\u8D8A\u8BE6\u7EC6\u8D8A\u597D\u3002\u793A\u4F8B\uFF1A\u9762\u8BD5\u5B98\u95EE\uFF1A\u4E3A\u4EC0\u4E48\u9009\u4EA7\u54C1\u65B9\u5411\uFF1F\u6211\u7B54\uFF1A...",
    value: rawText,
    onChange: e => setRawText(e.target.value)
  }), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-400 mt-1"
  }, rawText.length, " \u5B57")), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 justify-end"
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "secondary",
    onClick: onClose
  }, "\u53D6\u6D88"), /*#__PURE__*/React.createElement(Button, {
    variant: "primary",
    onClick: submit,
    disabled: submitting
  }, submitting ? 'AI 分析中...' : '提交并查看分析'))));
}

// ==================== 通知中心 ====================
function NotificationsPage() {
  const {
    toast,
    refreshUser
  } = useApp();
  const [list, setList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showPref, setShowPref] = useState(false);
  const load = async () => {
    try {
      const r = await apiCall('/api/notifications');
      setList(r.notifications || []);
    } catch (e) {
      toast(e.message, 'error');
    }
    setLoading(false);
  };
  useEffect(() => {
    load();
  }, []);
  const markRead = async id => {
    try {
      await apiCall('/api/notifications/' + id + '/read', {
        method: 'POST'
      });
      load();
      refreshUser();
    } catch {}
  };
  const markAllRead = async () => {
    try {
      await apiCall('/api/notifications/read-all', {
        method: 'POST'
      });
      toast('已全部标记已读', 'success');
      load();
      refreshUser();
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  const del = async id => {
    try {
      await apiCall('/api/notifications/' + id, {
        method: 'DELETE'
      });
      load();
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  const typeLabel = t => ({
    status_change: '📊 状态变更',
    review_missing: '📝 待复盘',
    profile_insight: '🧠 画像洞察',
    suggestion: '💡 AI 建议',
    resume_stale: '📄 简历提醒',
    card_liked: '👍 面经被赞',
    question_asked: '💬 新提问',
    question_replied: '✉️ 回复提醒'
  })[t] || t;
  const unread = list.filter(n => n.read === 0);
  return /*#__PURE__*/React.createElement("div", {
    className: "animate-slide-up"
  }, /*#__PURE__*/React.createElement(PageHeader, {
    title: "\u901A\u77E5\u4E2D\u5FC3",
    desc: unread.length + ' 条未读 · 共 ' + list.length + ' 条',
    action: /*#__PURE__*/React.createElement("div", {
      className: "flex gap-2"
    }, /*#__PURE__*/React.createElement(Button, {
      variant: "secondary",
      onClick: () => setShowPref(true)
    }, "\u504F\u597D\u8BBE\u7F6E"), unread.length > 0 && /*#__PURE__*/React.createElement(Button, {
      variant: "primary",
      onClick: markAllRead
    }, "\u5168\u90E8\u5DF2\u8BFB"))
  }), loading ? /*#__PURE__*/React.createElement(Card, {
    className: "p-8 text-center text-gray-400 text-sm"
  }, "\u52A0\u8F7D\u4E2D...") : list.length === 0 ? /*#__PURE__*/React.createElement(Card, {
    className: "p-0"
  }, /*#__PURE__*/React.createElement(EmptyState, {
    icon: "\uD83D\uDD14",
    title: "\u6682\u65E0\u901A\u77E5",
    desc: "\u5F53\u6709\u5C97\u4F4D\u72B6\u6001\u53D8\u66F4\u3001AI \u6D1E\u5BDF\u3001\u6216\u5F85\u590D\u76D8\u63D0\u9192\u65F6\u4F1A\u51FA\u73B0\u5728\u8FD9\u91CC"
  })) : /*#__PURE__*/React.createElement("div", {
    className: "space-y-2"
  }, list.map(n => /*#__PURE__*/React.createElement(Card, {
    key: n.id,
    className: 'p-4 ' + (n.read === 0 ? 'border-brand-200 bg-brand-50/30' : '')
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-start gap-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex-1 min-w-0"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-2 flex-wrap mb-1"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-xs font-medium text-gray-600"
  }, typeLabel(n.type)), n.read === 0 && /*#__PURE__*/React.createElement("span", {
    className: "w-1.5 h-1.5 rounded-full bg-brand-500"
  }), /*#__PURE__*/React.createElement("span", {
    className: "text-[10px] text-gray-400"
  }, relTime(n.created_at))), /*#__PURE__*/React.createElement("div", {
    className: "text-sm font-semibold text-gray-900"
  }, n.title), n.content && /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-600 mt-1 whitespace-pre-wrap"
  }, n.content)), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-1"
  }, n.read === 0 && /*#__PURE__*/React.createElement(Button, {
    size: "sm",
    variant: "ghost",
    onClick: () => markRead(n.id)
  }, "\u5DF2\u8BFB"), /*#__PURE__*/React.createElement("button", {
    onClick: () => del(n.id),
    className: "text-gray-400 hover:text-rose-600 p-1 transition"
  }, /*#__PURE__*/React.createElement(Icon.X, {
    className: "w-3.5 h-3.5"
  }))))))), showPref && /*#__PURE__*/React.createElement(NotifPrefModal, {
    onClose: () => setShowPref(false)
  }));
}
function NotifPrefModal({
  onClose
}) {
  const {
    toast
  } = useApp();
  const [pref, setPref] = useState(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    apiCall('/api/notifications/preferences').then(r => {
      setPref(r.preferences);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);
  const toggle = async key => {
    const newPref = {
      ...pref,
      [key]: pref[key] ? 0 : 1
    };
    setPref(newPref);
    try {
      await apiCall('/api/notifications/preferences', {
        method: 'POST',
        body: JSON.stringify(newPref)
      });
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  if (loading || !pref) return /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: onClose,
    title: "\u901A\u77E5\u504F\u597D"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-sm text-gray-400 py-4 text-center"
  }, "\u52A0\u8F7D\u4E2D..."));
  const items = [{
    key: 'status_change',
    label: '岗位状态变更'
  }, {
    key: 'review_missing',
    label: '面试后未复盘提醒'
  }, {
    key: 'profile_insight',
    label: '画像自审洞察'
  }, {
    key: 'suggestion',
    label: 'AI 建议生成通知'
  }, {
    key: 'resume_stale',
    label: '简历长期未更新（暂未启用）'
  }, {
    key: 'card_liked',
    label: '面经卡被赞'
  }, {
    key: 'question_asked',
    label: '有人向我提问'
  }, {
    key: 'question_replied',
    label: '我的问题有了回复'
  }];
  return /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: onClose,
    title: "\u901A\u77E5\u504F\u597D"
  }, /*#__PURE__*/React.createElement("div", {
    className: "space-y-2"
  }, items.map(it => /*#__PURE__*/React.createElement("label", {
    key: it.key,
    className: "flex items-center justify-between p-3 rounded-lg border border-gray-100 hover:bg-gray-50 transition cursor-pointer"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-sm text-gray-800"
  }, it.label), /*#__PURE__*/React.createElement("input", {
    type: "checkbox",
    checked: pref[it.key] === 1,
    onChange: () => toggle(it.key),
    className: "w-4 h-4 rounded accent-brand-600"
  })))));
}

// ==================== 设置页 ====================
function SettingsPage() {
  const {
    user,
    toast,
    refreshUser
  } = useApp();
  const [quota, setQuota] = useState(null);
  const [byok, setByok] = useState('');
  const [saving, setSaving] = useState(false);
  const [emailModal, setEmailModal] = useState(false);
  const [resetModal, setResetModal] = useState(false);
  const [resetConfirmText, setResetConfirmText] = useState('');
  useEffect(() => {
    apiCall('/api/me/quota').then(r => setQuota(r)).catch(() => {});
  }, []);
  const saveByok = async () => {
    setSaving(true);
    try {
      const r = await apiCall('/api/me/byok', {
        method: 'POST',
        body: JSON.stringify({
          api_key: byok.trim()
        })
      });
      toast(r.has_key ? '已保存你的 API Key，今后调用不占免费配额' : '已清除', 'success');
      setByok('');
      refreshUser();
      apiCall('/api/me/quota').then(r => setQuota(r)).catch(() => {});
    } catch (e) {
      toast(e.message, 'error');
    }
    setSaving(false);
  };
  return /*#__PURE__*/React.createElement("div", {
    className: "animate-slide-up space-y-5"
  }, /*#__PURE__*/React.createElement(PageHeader, {
    title: "\u8BBE\u7F6E",
    desc: "\u4E2A\u4EBA\u4FE1\u606F \xB7 \u914D\u989D \xB7 \u901A\u77E5\u504F\u597D \xB7 \u8D26\u53F7\u6062\u590D"
  }), /*#__PURE__*/React.createElement(Card, {
    className: "p-5"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "font-semibold text-gray-900 mb-3"
  }, "\u8D26\u53F7"), /*#__PURE__*/React.createElement("div", {
    className: "space-y-2 text-sm"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-gray-500"
  }, "\u7528\u6237 ID"), /*#__PURE__*/React.createElement("span", {
    className: "text-gray-900 font-mono text-xs"
  }, user?.id)), /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-gray-500"
  }, "\u59D3\u540D"), /*#__PURE__*/React.createElement("span", {
    className: "text-gray-900"
  }, user?.name || '未设置')), /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-gray-500"
  }, "\u6C42\u804C\u65B9\u5411"), /*#__PURE__*/React.createElement("span", {
    className: "text-gray-900"
  }, user?.target_track || '未设置')), /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between items-center"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-gray-500"
  }, "\u7ED1\u5B9A\u90AE\u7BB1\uFF08\u8DE8\u8BBE\u5907\u6062\u590D\uFF09"), /*#__PURE__*/React.createElement(Button, {
    size: "sm",
    variant: "secondary",
    onClick: () => setEmailModal(true)
  }, "\u7ED1\u5B9A\u90AE\u7BB1")), /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between items-center pt-2 border-t border-gray-100"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-gray-500"
  }, "\u91CD\u7F6E\u8D26\u53F7"), /*#__PURE__*/React.createElement(Button, {
    size: "sm",
    variant: "danger",
    onClick: () => {
      setResetConfirmText('');
      setResetModal(true);
    }
  }, "\u91CD\u7F6E\u8D26\u53F7")))), quota && /*#__PURE__*/React.createElement(Card, {
    className: "p-5"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "font-semibold text-gray-900 mb-3"
  }, "\u4ECA\u65E5 AI \u914D\u989D"), /*#__PURE__*/React.createElement("div", {
    className: "space-y-3"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between text-sm mb-1"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-gray-700"
  }, "\u5FEB\u901F AI\uFF08Flash\uFF09"), /*#__PURE__*/React.createElement("span", {
    className: "text-gray-900 font-semibold"
  }, quota.flash.used, " / ", quota.flash.limit)), /*#__PURE__*/React.createElement("div", {
    className: "h-1.5 rounded-full bg-gray-100 overflow-hidden"
  }, /*#__PURE__*/React.createElement("div", {
    className: "h-full bg-brand-500 transition-all",
    style: {
      width: Math.min(100, quota.flash.used / quota.flash.limit * 100) + '%'
    }
  }))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between text-sm mb-1"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-gray-700"
  }, "\u6DF1\u5EA6 AI\uFF08Pro\uFF09"), /*#__PURE__*/React.createElement("span", {
    className: "text-gray-900 font-semibold"
  }, quota.pro.used, " / ", quota.pro.limit)), /*#__PURE__*/React.createElement("div", {
    className: "h-1.5 rounded-full bg-gray-100 overflow-hidden"
  }, /*#__PURE__*/React.createElement("div", {
    className: "h-full bg-accent-500 transition-all",
    style: {
      width: Math.min(100, quota.pro.used / quota.pro.limit * 100) + '%'
    }
  }))), quota.using_own_key && /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-emerald-700 bg-emerald-50 rounded p-2 border border-emerald-200"
  }, "\u2713 \u4F60\u6B63\u5728\u4F7F\u7528\u81EA\u5DF1\u7684 DeepSeek API Key\uFF0C\u4ECA\u65E5\u8C03\u7528\u4E0D\u5360\u514D\u8D39\u914D\u989D"))), /*#__PURE__*/React.createElement(Card, {
    className: "p-5"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "font-semibold text-gray-900 mb-2"
  }, "\u4F7F\u7528\u81EA\u5DF1\u7684 DeepSeek API Key\uFF08BYOK\uFF09"), /*#__PURE__*/React.createElement("p", {
    className: "text-xs text-gray-600 mb-3 leading-relaxed"
  }, "\u914D\u989D\u7528\u5B8C\u8FD8\u60F3\u7EE7\u7EED\u7528\uFF1F\u586B\u5165\u4F60\u81EA\u5DF1\u7684 DeepSeek API Key\uFF0C\u4ECA\u540E\u6240\u6709 AI \u8C03\u7528\u90FD\u8D70\u4F60\u7684 Key\uFF08\u6570\u636E\u66F4\u79C1\u5BC6 \xB7 \u65E0\u914D\u989D\u9650\u5236\uFF09\u3002", /*#__PURE__*/React.createElement("br", null), /*#__PURE__*/React.createElement("a", {
    href: "https://platform.deepseek.com",
    target: "_blank",
    rel: "noopener noreferrer",
    className: "text-brand-600 hover:underline"
  }, "\uD83D\uDC49 \u53BB DeepSeek \u83B7\u53D6 API Key")), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2"
  }, /*#__PURE__*/React.createElement("input", {
    type: "password",
    className: "flex-1 px-3 py-2 rounded-lg border border-gray-300 text-sm font-mono",
    placeholder: user?.email ? 'sk-...（留空清除）' : 'sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    value: byok,
    onChange: e => setByok(e.target.value)
  }), /*#__PURE__*/React.createElement(Button, {
    variant: "primary",
    onClick: saveByok,
    disabled: saving
  }, saving ? '保存中...' : '保存'))), /*#__PURE__*/React.createElement(Card, {
    className: "p-5 bg-amber-50/50 border-amber-100"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "font-semibold text-gray-900 mb-2"
  }, "\u5173\u4E8E\u6362\u8BBE\u5907"), /*#__PURE__*/React.createElement("p", {
    className: "text-xs text-gray-700 leading-relaxed"
  }, "\u76EE\u524D\u6362\u8BBE\u5907\u767B\u5F55\u4F1A\u521B\u5EFA\u65B0\u8D26\u53F7\uFF0C\u6570\u636E\u4E0D\u4E92\u901A\u3002", /*#__PURE__*/React.createElement("br", null), /*#__PURE__*/React.createElement("strong", null, "\u90AE\u7BB1\u7ED1\u5B9A + \u6062\u590D"), "\u529F\u80FD\u8FD8\u6CA1\u5B9E\u88C5\uFF0C\u672A\u6765\u7248\u672C\u4E2D\u5C06\u4F1A\u66F4\u65B0\u3002 \u5728\u90A3\u4E4B\u524D\uFF0C\u5EFA\u8BAE\u4F7F\u7528\u540C\u4E00\u8BBE\u5907 + \u6D4F\u89C8\u5668\u3002")), resetModal && /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: () => setResetModal(false),
    title: "\u91CD\u7F6E\u8D26\u53F7"
  }, /*#__PURE__*/React.createElement("div", {
    className: "space-y-4"
  }, /*#__PURE__*/React.createElement("div", {
    className: "p-4 rounded-lg bg-red-50 border border-red-200"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-sm font-medium text-red-900 mb-1"
  }, "\u26A0\uFE0F \u6B64\u64CD\u4F5C\u4E0D\u53EF\u64A4\u9500"), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-red-700 leading-relaxed"
  }, "\u5C06\u6E05\u9664\u4F60\u7684\u6240\u6709\u6570\u636E\uFF1A\u7B80\u5386\u3001JD\u3001\u5C97\u4F4D\u8BB0\u5F55\u3001\u9762\u8BD5\u9898\u3001\u590D\u76D8\u3001\u753B\u50CF\u6807\u7B7E\u3001\u901A\u77E5\u8BB0\u5F55\u7B49\u3002", /*#__PURE__*/React.createElement("br", null), "\u8D26\u53F7\u5C06\u6062\u590D\u4E3A\u521D\u59CB\u72B6\u6001\uFF0C\u91CD\u65B0\u8D70\u5F15\u5BFC\u6D41\u7A0B\u3002")), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "block text-sm text-gray-700 mb-1"
  }, "\u8BF7\u8F93\u5165 ", /*#__PURE__*/React.createElement("span", {
    className: "font-mono font-semibold text-red-600"
  }, "\u786E\u8BA4\u91CD\u7F6E"), " \u4EE5\u7EE7\u7EED"), /*#__PURE__*/React.createElement("input", {
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm font-mono",
    placeholder: "\u786E\u8BA4\u91CD\u7F6E",
    value: resetConfirmText,
    onChange: e => setResetConfirmText(e.target.value)
  })), /*#__PURE__*/React.createElement("div", {
    className: "flex justify-end gap-2"
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "secondary",
    onClick: () => setResetModal(false)
  }, "\u53D6\u6D88"), /*#__PURE__*/React.createElement(Button, {
    variant: "danger",
    disabled: resetConfirmText !== '确认重置',
    onClick: async () => {
      try {
        await apiCall('/api/me/reset', {
          method: 'POST'
        });
        localStorage.removeItem('onboarding_dismissed');
        setResetModal(false);
        toast('账号已重置，正在重新加载…', 'success');
        setTimeout(() => location.reload(), 800);
      } catch (e) {
        toast(e.message, 'error');
      }
    }
  }, "\u786E\u8BA4\u91CD\u7F6E")))), emailModal && /*#__PURE__*/React.createElement(EmailBindPlaceholderModal, {
    onClose: () => setEmailModal(false)
  }));
}
function EmailBindPlaceholderModal({
  onClose
}) {
  return /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: onClose,
    title: "\u90AE\u7BB1\u7ED1\u5B9A"
  }, /*#__PURE__*/React.createElement("div", {
    className: "space-y-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "p-4 rounded-lg bg-amber-50 border border-amber-200"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-sm font-medium text-amber-900 mb-1"
  }, "\u8BE5\u529F\u80FD\u8FD8\u6CA1\u5B9E\u88C5"), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-amber-700 leading-relaxed"
  }, "\u90AE\u7BB1\u7ED1\u5B9A\u548C\u8DE8\u8BBE\u5907\u6062\u590D\u529F\u80FD\uFF0C\u672A\u6765\u7248\u672C\u4E2D\u5C06\u4F1A\u66F4\u65B0\u3002", /*#__PURE__*/React.createElement("br", null), "\u5728\u90A3\u4E4B\u524D\uFF0C\u6570\u636E\u4F1A\u7ED1\u5B9A\u5230\u5F53\u524D\u6D4F\u89C8\u5668/\u8BBE\u5907\u3002")), /*#__PURE__*/React.createElement("div", {
    className: "flex justify-end"
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "secondary",
    onClick: onClose
  }, "\u6211\u77E5\u9053\u4E86"))));
}

// ==================== 管理员面板 ====================
function AdminPage() {
  const {
    toast
  } = useApp();
  const [stats, setStats] = useState(null);
  const [tab, setTab] = useState('stats');
  useEffect(() => {
    apiCall('/api/admin/stats').then(setStats).catch(e => toast(e.message, 'error'));
  }, []);
  return /*#__PURE__*/React.createElement("div", {
    className: "animate-slide-up space-y-5"
  }, /*#__PURE__*/React.createElement(PageHeader, {
    title: "\u7BA1\u7406\u9762\u677F",
    desc: "\u4EC5\u7BA1\u7406\u5458\u53EF\u89C1 \xB7 \u5168\u5C40\u6570\u636E / \u7528\u6237 / LLM \u65E5\u5FD7"
  }), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 border-b border-gray-200 overflow-x-auto"
  }, [{
    key: 'stats',
    label: '📊 数据看板'
  }, {
    key: 'users',
    label: '👥 用户'
  }, {
    key: 'logs',
    label: '📝 LLM 日志'
  }, {
    key: 'cron',
    label: '⏰ 定时任务'
  }, {
    key: 'config',
    label: '⚙️ 配置'
  }].map(t => /*#__PURE__*/React.createElement("button", {
    key: t.key,
    onClick: () => setTab(t.key),
    className: 'px-3 py-2 text-sm font-medium transition border-b-2 -mb-px whitespace-nowrap ' + (tab === t.key ? 'border-brand-600 text-brand-700' : 'border-transparent text-gray-600 hover:text-gray-900')
  }, t.label))), tab === 'stats' && /*#__PURE__*/React.createElement(AdminStats, {
    stats: stats
  }), tab === 'users' && /*#__PURE__*/React.createElement(AdminUsers, null), tab === 'logs' && /*#__PURE__*/React.createElement(AdminLogs, null), tab === 'cron' && /*#__PURE__*/React.createElement(AdminCron, null), tab === 'config' && /*#__PURE__*/React.createElement(AdminConfig, null));
}
function AdminStats({
  stats
}) {
  if (!stats) return /*#__PURE__*/React.createElement(Card, {
    className: "p-8 text-center text-gray-400 text-sm"
  }, "\u52A0\u8F7D\u4E2D...");
  return /*#__PURE__*/React.createElement("div", {
    className: "space-y-4"
  }, /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-2 md:grid-cols-4 gap-3"
  }, /*#__PURE__*/React.createElement(StatCard, {
    label: "\u7528\u6237\u603B\u6570",
    value: stats.users.total
  }), /*#__PURE__*/React.createElement(StatCard, {
    label: "\u4ECA\u65E5\u6D3B\u8DC3",
    value: stats.users.active_today
  }), /*#__PURE__*/React.createElement(StatCard, {
    label: "\u5DF2\u5B8C\u6210\u5F15\u5BFC",
    value: stats.users.onboarded
  }), /*#__PURE__*/React.createElement(StatCard, {
    label: "\u4ECA\u65E5\u7528\u8FC7\u914D\u989D\u7684\u4EBA",
    value: stats.quota_today.users_with_usage
  })), /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-2 md:grid-cols-4 gap-3"
  }, /*#__PURE__*/React.createElement(StatCard, {
    label: "\u7B80\u5386\u603B\u6570",
    value: stats.content.resumes
  }), /*#__PURE__*/React.createElement(StatCard, {
    label: "JD \u603B\u6570",
    value: stats.content.jds
  }), /*#__PURE__*/React.createElement(StatCard, {
    label: "\u5C97\u4F4D\u603B\u6570",
    value: stats.content.positions
  }), /*#__PURE__*/React.createElement(StatCard, {
    label: "\u590D\u76D8\u603B\u6570",
    value: stats.content.reviews
  })), /*#__PURE__*/React.createElement(Card, {
    className: "p-5"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "font-semibold text-gray-900 mb-3"
  }, "LLM \u8C03\u7528\uFF08\u4ECA\u65E5 / \u672C\u5468 / \u672C\u6708\uFF09"), /*#__PURE__*/React.createElement(LLMUsageTable, {
    title: "\u4ECA\u65E5",
    rows: stats.llm.today
  }), /*#__PURE__*/React.createElement(LLMUsageTable, {
    title: "\u672C\u5468",
    rows: stats.llm.week
  }), /*#__PURE__*/React.createElement(LLMUsageTable, {
    title: "\u672C\u6708",
    rows: stats.llm.month
  })), /*#__PURE__*/React.createElement(Card, {
    className: "p-5"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "font-semibold text-gray-900 mb-3"
  }, "\u4ECA\u65E5\u914D\u989D\u6D88\u8017"), /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-2 gap-3 text-sm"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between p-3 rounded bg-brand-50"
  }, /*#__PURE__*/React.createElement("span", null, "Flash\uFF08\u5168\u5C40\uFF09"), /*#__PURE__*/React.createElement("span", {
    className: "font-semibold text-brand-700"
  }, stats.quota_today.flash_used_total)), /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between p-3 rounded bg-accent-500/10"
  }, /*#__PURE__*/React.createElement("span", null, "Pro\uFF08\u5168\u5C40\uFF09"), /*#__PURE__*/React.createElement("span", {
    className: "font-semibold text-accent-600"
  }, stats.quota_today.pro_used_total)))));
}
function StatCard({
  label,
  value
}) {
  return /*#__PURE__*/React.createElement(Card, {
    className: "p-4"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-500"
  }, label), /*#__PURE__*/React.createElement("div", {
    className: "text-2xl font-bold text-gray-900 mt-1"
  }, value));
}
function LLMUsageTable({
  title,
  rows
}) {
  if (!rows || rows.length === 0) return /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-400 py-2"
  }, title, "\uFF1A\u65E0\u8C03\u7528");
  return /*#__PURE__*/React.createElement("div", {
    className: "mb-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-xs font-semibold text-gray-700 mb-1"
  }, title), /*#__PURE__*/React.createElement("div", {
    className: "space-y-1"
  }, rows.map((r, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    className: "flex justify-between text-xs p-2 rounded bg-gray-50"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-gray-700 font-mono"
  }, r.model), /*#__PURE__*/React.createElement("span", {
    className: "text-gray-600"
  }, r.calls, " \u6B21 \xB7 ", r.tokens || 0, " tokens")))));
}
function AdminUsers() {
  const {
    toast
  } = useApp();
  const [list, setList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [detail, setDetail] = useState(null);
  useEffect(() => {
    apiCall('/api/admin/users').then(r => {
      setList(r.users || []);
      setLoading(false);
    }).catch(e => toast(e.message, 'error'));
  }, []);
  if (loading) return /*#__PURE__*/React.createElement(Card, {
    className: "p-8 text-center text-gray-400 text-sm"
  }, "\u52A0\u8F7D\u4E2D...");
  return /*#__PURE__*/React.createElement(Card, {
    className: "p-0 overflow-x-auto"
  }, /*#__PURE__*/React.createElement("table", {
    className: "w-full text-sm"
  }, /*#__PURE__*/React.createElement("thead", {
    className: "bg-gray-50 text-xs text-gray-500 uppercase"
  }, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", {
    className: "px-4 py-3 text-left"
  }, "\u7528\u6237"), /*#__PURE__*/React.createElement("th", {
    className: "px-4 py-3 text-left"
  }, "\u65B9\u5411"), /*#__PURE__*/React.createElement("th", {
    className: "px-4 py-3 text-right"
  }, "\u7B80\u5386"), /*#__PURE__*/React.createElement("th", {
    className: "px-4 py-3 text-right"
  }, "JD"), /*#__PURE__*/React.createElement("th", {
    className: "px-4 py-3 text-right"
  }, "\u5C97\u4F4D"), /*#__PURE__*/React.createElement("th", {
    className: "px-4 py-3 text-right"
  }, "\u590D\u76D8"), /*#__PURE__*/React.createElement("th", {
    className: "px-4 py-3 text-right"
  }, "\u4ECA\u65E5\u914D\u989D"), /*#__PURE__*/React.createElement("th", {
    className: "px-4 py-3 text-right"
  }, "\u64CD\u4F5C"))), /*#__PURE__*/React.createElement("tbody", {
    className: "divide-y divide-gray-100"
  }, list.map(u => /*#__PURE__*/React.createElement("tr", {
    key: u.id,
    className: "hover:bg-gray-50"
  }, /*#__PURE__*/React.createElement("td", {
    className: "px-4 py-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "font-medium text-gray-900"
  }, u.name || '未命名', u.is_admin === 1 && /*#__PURE__*/React.createElement("span", {
    className: "ml-1 text-[10px] text-brand-700"
  }, "[\u7BA1\u7406\u5458]")), /*#__PURE__*/React.createElement("div", {
    className: "text-xs text-gray-500"
  }, u.email || '匿名')), /*#__PURE__*/React.createElement("td", {
    className: "px-4 py-3 text-gray-600 text-xs"
  }, u.target_track || '—'), /*#__PURE__*/React.createElement("td", {
    className: "px-4 py-3 text-right text-gray-700"
  }, u.resumes_count), /*#__PURE__*/React.createElement("td", {
    className: "px-4 py-3 text-right text-gray-700"
  }, u.jds_count), /*#__PURE__*/React.createElement("td", {
    className: "px-4 py-3 text-right text-gray-700"
  }, u.positions_count), /*#__PURE__*/React.createElement("td", {
    className: "px-4 py-3 text-right text-gray-700"
  }, u.reviews_count), /*#__PURE__*/React.createElement("td", {
    className: "px-4 py-3 text-right text-xs"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-brand-700"
  }, u.flash_today, "F"), " / ", /*#__PURE__*/React.createElement("span", {
    className: "text-accent-600"
  }, u.pro_today, "P"), u.has_own_key === 1 && /*#__PURE__*/React.createElement("span", {
    className: "ml-1 text-[10px] text-emerald-600"
  }, "\uD83D\uDD11")), /*#__PURE__*/React.createElement("td", {
    className: "px-4 py-3 text-right"
  }, /*#__PURE__*/React.createElement(Button, {
    size: "sm",
    variant: "ghost",
    onClick: () => setDetail(u.id)
  }, "\u8BE6\u60C5")))))), detail && /*#__PURE__*/React.createElement(AdminUserDetailModal, {
    uid: detail,
    onClose: () => setDetail(null)
  }));
}
function AdminUserDetailModal({
  uid,
  onClose
}) {
  const [data, setData] = useState(null);
  useEffect(() => {
    apiCall('/api/admin/users/' + uid).then(setData);
  }, [uid]);
  return /*#__PURE__*/React.createElement(Modal, {
    open: true,
    onClose: onClose,
    title: "\u7528\u6237\u8BE6\u60C5",
    maxWidth: "max-w-3xl"
  }, !data ? /*#__PURE__*/React.createElement("div", {
    className: "text-sm text-gray-400 py-4 text-center"
  }, "\u52A0\u8F7D\u4E2D...") : /*#__PURE__*/React.createElement("div", {
    className: "space-y-4 text-sm"
  }, /*#__PURE__*/React.createElement("div", {
    className: "p-3 rounded bg-gray-50 text-xs"
  }, /*#__PURE__*/React.createElement("div", null, "ID: ", /*#__PURE__*/React.createElement("span", {
    className: "font-mono"
  }, data.user.id)), /*#__PURE__*/React.createElement("div", null, "\u6307\u7EB9: ", /*#__PURE__*/React.createElement("span", {
    className: "font-mono text-gray-600"
  }, data.user.fingerprint?.slice(0, 20), "...")), /*#__PURE__*/React.createElement("div", null, "\u90AE\u7BB1: ", data.user.email || '—'), /*#__PURE__*/React.createElement("div", null, "\u6700\u540E\u6D3B\u8DC3: ", data.user.last_active_at ? new Date(data.user.last_active_at).toLocaleString('zh-CN') : '—'), data.user.own_api_key_masked && /*#__PURE__*/React.createElement("div", null, "BYOK Key: ", /*#__PURE__*/React.createElement("span", {
    className: "font-mono"
  }, data.user.own_api_key_masked))), /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-4 gap-2 text-xs"
  }, /*#__PURE__*/React.createElement("div", {
    className: "p-2 rounded bg-brand-50 text-center"
  }, /*#__PURE__*/React.createElement("div", {
    className: "font-semibold"
  }, data.resumes?.length || 0), /*#__PURE__*/React.createElement("div", {
    className: "text-gray-500"
  }, "\u7B80\u5386")), /*#__PURE__*/React.createElement("div", {
    className: "p-2 rounded bg-brand-50 text-center"
  }, /*#__PURE__*/React.createElement("div", {
    className: "font-semibold"
  }, data.jds?.length || 0), /*#__PURE__*/React.createElement("div", {
    className: "text-gray-500"
  }, "JD")), /*#__PURE__*/React.createElement("div", {
    className: "p-2 rounded bg-brand-50 text-center"
  }, /*#__PURE__*/React.createElement("div", {
    className: "font-semibold"
  }, data.positions?.length || 0), /*#__PURE__*/React.createElement("div", {
    className: "text-gray-500"
  }, "\u5C97\u4F4D")), /*#__PURE__*/React.createElement("div", {
    className: "p-2 rounded bg-brand-50 text-center"
  }, /*#__PURE__*/React.createElement("div", {
    className: "font-semibold"
  }, data.reviews?.length || 0), /*#__PURE__*/React.createElement("div", {
    className: "text-gray-500"
  }, "\u590D\u76D8"))), data.quota_history?.length > 0 && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "text-xs font-semibold text-gray-700 mb-2"
  }, "\u8FD1 14 \u5929\u914D\u989D"), /*#__PURE__*/React.createElement("div", {
    className: "space-y-1 text-xs"
  }, data.quota_history.map((q, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    className: "flex justify-between p-1.5 rounded hover:bg-gray-50"
  }, /*#__PURE__*/React.createElement("span", null, q.date), /*#__PURE__*/React.createElement("span", {
    className: "text-gray-600"
  }, "F ", q.flash_used, " / P ", q.pro_used, q.using_own_key === 1 && ' 🔑')))))));
}
function AdminLogs() {
  const {
    toast
  } = useApp();
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState({
    status: '',
    purpose: ''
  });
  const load = async () => {
    setLoading(true);
    try {
      const qs = new URLSearchParams({
        limit: '100',
        ...Object.fromEntries(Object.entries(filter).filter(([, v]) => v))
      });
      const r = await apiCall('/api/admin/llm-logs?' + qs);
      setLogs(r.logs || []);
    } catch (e) {
      toast(e.message, 'error');
    }
    setLoading(false);
  };
  useEffect(() => {
    load();
  }, [filter]);
  return /*#__PURE__*/React.createElement(Card, {
    className: "p-4"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 mb-3 flex-wrap"
  }, /*#__PURE__*/React.createElement("select", {
    className: "px-2 py-1 rounded border border-gray-300 text-xs bg-white",
    value: filter.status,
    onChange: e => setFilter({
      ...filter,
      status: e.target.value
    })
  }, /*#__PURE__*/React.createElement("option", {
    value: ""
  }, "\u6240\u6709\u72B6\u6001"), /*#__PURE__*/React.createElement("option", {
    value: "success"
  }, "\u6210\u529F"), /*#__PURE__*/React.createElement("option", {
    value: "failed"
  }, "\u5931\u8D25"), /*#__PURE__*/React.createElement("option", {
    value: "fallback"
  }, "\u964D\u7EA7")), /*#__PURE__*/React.createElement("select", {
    className: "px-2 py-1 rounded border border-gray-300 text-xs bg-white",
    value: filter.purpose,
    onChange: e => setFilter({
      ...filter,
      purpose: e.target.value
    })
  }, /*#__PURE__*/React.createElement("option", {
    value: ""
  }, "\u6240\u6709\u7528\u9014"), /*#__PURE__*/React.createElement("option", {
    value: "parse_resume"
  }, "\u7B80\u5386\u89E3\u6790"), /*#__PURE__*/React.createElement("option", {
    value: "parse_jd"
  }, "JD \u89E3\u6790"), /*#__PURE__*/React.createElement("option", {
    value: "parse_match_combined"
  }, "JD\u5408\u5E76"), /*#__PURE__*/React.createElement("option", {
    value: "match_quick"
  }, "\u7C97\u5339\u914D"), /*#__PURE__*/React.createElement("option", {
    value: "match_deep"
  }, "\u6DF1\u5EA6\u5339\u914D"), /*#__PURE__*/React.createElement("option", {
    value: "review_analyze"
  }, "\u590D\u76D8\u5206\u6790"), /*#__PURE__*/React.createElement("option", {
    value: "profile_from_resume"
  }, "\u753B\u50CF-\u7B80\u5386"), /*#__PURE__*/React.createElement("option", {
    value: "profile_from_jd"
  }, "\u753B\u50CF-JD"), /*#__PURE__*/React.createElement("option", {
    value: "profile_audit"
  }, "\u753B\u50CF\u81EA\u5BA1"), /*#__PURE__*/React.createElement("option", {
    value: "practice_generate"
  }, "\u966A\u7EC3\u751F\u6210"), /*#__PURE__*/React.createElement("option", {
    value: "suggestion_generate"
  }, "\u5EFA\u8BAE\u751F\u6210"))), loading ? /*#__PURE__*/React.createElement("div", {
    className: "text-sm text-gray-400 py-4 text-center"
  }, "\u52A0\u8F7D\u4E2D...") : /*#__PURE__*/React.createElement("div", {
    className: "overflow-x-auto"
  }, /*#__PURE__*/React.createElement("table", {
    className: "w-full text-xs"
  }, /*#__PURE__*/React.createElement("thead", {
    className: "text-gray-500"
  }, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", {
    className: "text-left p-2"
  }, "\u65F6\u95F4"), /*#__PURE__*/React.createElement("th", {
    className: "text-left p-2"
  }, "\u7528\u6237"), /*#__PURE__*/React.createElement("th", {
    className: "text-left p-2"
  }, "\u6A21\u578B"), /*#__PURE__*/React.createElement("th", {
    className: "text-left p-2"
  }, "\u7528\u9014"), /*#__PURE__*/React.createElement("th", {
    className: "text-right p-2"
  }, "Tokens"), /*#__PURE__*/React.createElement("th", {
    className: "text-right p-2"
  }, "\u8017\u65F6"), /*#__PURE__*/React.createElement("th", {
    className: "text-left p-2"
  }, "\u72B6\u6001"))), /*#__PURE__*/React.createElement("tbody", {
    className: "divide-y divide-gray-100"
  }, logs.map(l => /*#__PURE__*/React.createElement("tr", {
    key: l.id,
    className: "hover:bg-gray-50"
  }, /*#__PURE__*/React.createElement("td", {
    className: "p-2 font-mono text-gray-600"
  }, new Date(l.created_at).toLocaleTimeString('zh-CN')), /*#__PURE__*/React.createElement("td", {
    className: "p-2 text-gray-700"
  }, l.name || l.email || l.user_id?.slice(0, 10) || '—'), /*#__PURE__*/React.createElement("td", {
    className: "p-2 font-mono text-[10px] text-gray-500"
  }, l.model?.replace('deepseek-', '') || '—'), /*#__PURE__*/React.createElement("td", {
    className: "p-2 text-gray-700"
  }, l.purpose), /*#__PURE__*/React.createElement("td", {
    className: "p-2 text-right text-gray-600"
  }, (l.input_tokens || 0) + (l.output_tokens || 0)), /*#__PURE__*/React.createElement("td", {
    className: "p-2 text-right text-gray-600"
  }, l.duration_ms, "ms"), /*#__PURE__*/React.createElement("td", {
    className: "p-2"
  }, /*#__PURE__*/React.createElement("span", {
    className: 'px-1.5 py-0.5 rounded text-[10px] ' + (l.status === 'success' ? 'bg-emerald-50 text-emerald-700' : l.status === 'fallback' ? 'bg-amber-50 text-amber-700' : 'bg-rose-50 text-rose-700')
  }, l.status)))), logs.length === 0 && /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("td", {
    colSpan: "7",
    className: "text-center py-4 text-gray-400"
  }, "\u65E0\u6570\u636E"))))));
}
function AdminCron() {
  const {
    toast
  } = useApp();
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);
  const run = async () => {
    if (!confirm('手动触发每日任务？会检查所有用户的未复盘提醒 + 对符合条件的画像自审（可能消耗多次 Pro 配额）')) return;
    setRunning(true);
    try {
      const r = await apiCall('/api/admin/cron/run-daily', {
        method: 'POST'
      });
      setResult(r.summary);
      toast('执行完成', 'success');
    } catch (e) {
      toast(e.message, 'error');
    }
    setRunning(false);
  };
  return /*#__PURE__*/React.createElement(Card, {
    className: "p-5"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "font-semibold text-gray-900 mb-2"
  }, "\u6BCF\u65E5 Cron \u4EFB\u52A1"), /*#__PURE__*/React.createElement("p", {
    className: "text-sm text-gray-600 mb-4"
  }, "Cloudflare Cron \u5B9A\u65F6\u5728\u5317\u4EAC\u65F6\u95F4 09:00 \u81EA\u52A8\u8DD1\u3002\u4E5F\u53EF\u4EE5\u624B\u52A8\u89E6\u53D1\u7528\u4E8E\u6D4B\u8BD5\u3002"), /*#__PURE__*/React.createElement(Button, {
    variant: "primary",
    onClick: run,
    disabled: running
  }, running ? '执行中...' : '▶️ 立即执行'), result && /*#__PURE__*/React.createElement("div", {
    className: "mt-4 p-3 rounded bg-gray-50 text-xs font-mono"
  }, /*#__PURE__*/React.createElement("div", null, "\u9762\u8BD5\u672A\u590D\u76D8\u63D0\u9192\uFF1A\u63A8\u9001 ", result.review_reminder?.reminded_users || 0, " \u4E2A\u7528\u6237\uFF08\u5171 ", result.review_reminder?.pending_reviews || 0, " \u573A\u9762\u8BD5\uFF09"), /*#__PURE__*/React.createElement("div", null, "\u753B\u50CF\u81EA\u5BA1\uFF1A\u5904\u7406 ", result.profile_audit?.processed || 0, " \u4E2A\u7528\u6237 \xB7 \u5931\u8D25 ", result.profile_audit?.failed || 0), /*#__PURE__*/React.createElement("div", {
    className: "text-gray-400 mt-1"
  }, "\u8017\u65F6\uFF1A", result.started_at, " \u2192 ", result.finished_at)));
}
function AdminConfig() {
  const {
    toast
  } = useApp();
  const [config, setConfig] = useState(null);
  const [flashQuota, setFlashQuota] = useState(50);
  const [proQuota, setProQuota] = useState(5);
  const [saving, setSaving] = useState(false);
  useEffect(() => {
    apiCall('/api/admin/config').then(r => {
      setConfig(r);
      setFlashQuota(r.quota.FAST);
      setProQuota(r.quota.PRO);
    }).catch(() => {});
  }, []);
  const save = async () => {
    setSaving(true);
    try {
      await apiCall('/api/admin/config', {
        method: 'POST',
        body: JSON.stringify({
          flash_quota: flashQuota,
          pro_quota: proQuota
        })
      });
      toast('已保存（运行时生效，Worker 重启后恢复默认）', 'success');
    } catch (e) {
      toast(e.message, 'error');
    }
    setSaving(false);
  };
  if (!config) return /*#__PURE__*/React.createElement(Card, {
    className: "p-8 text-center text-gray-400 text-sm"
  }, "\u52A0\u8F7D\u4E2D...");
  return /*#__PURE__*/React.createElement(Card, {
    className: "p-5 space-y-4"
  }, /*#__PURE__*/React.createElement("h3", {
    className: "font-semibold text-gray-900"
  }, "\u5168\u5C40\u914D\u7F6E"), /*#__PURE__*/React.createElement("div", {
    className: "space-y-2 text-sm"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-gray-500"
  }, "\u7248\u672C"), /*#__PURE__*/React.createElement("span", null, config.version)), /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-gray-500"
  }, "\u90AE\u4EF6\u53D1\u4EF6\u4EBA"), /*#__PURE__*/React.createElement("span", {
    className: "font-mono text-xs"
  }, config.email_from)), /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-gray-500"
  }, "Flash \u6A21\u578B"), /*#__PURE__*/React.createElement("span", {
    className: "font-mono text-xs"
  }, config.models.FAST)), /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-gray-500"
  }, "Pro \u6A21\u578B"), /*#__PURE__*/React.createElement("span", {
    className: "font-mono text-xs"
  }, config.models.PRO))), /*#__PURE__*/React.createElement("div", {
    className: "pt-3 border-t border-gray-100"
  }, /*#__PURE__*/React.createElement("h4", {
    className: "font-medium text-gray-900 text-sm mb-2"
  }, "\u6BCF\u65E5\u914D\u989D"), /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-2 gap-3"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs text-gray-600 mb-1 block"
  }, "Flash / \u5929"), /*#__PURE__*/React.createElement("input", {
    type: "number",
    min: "1",
    max: "500",
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm",
    value: flashQuota,
    onChange: e => setFlashQuota(Number(e.target.value))
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "text-xs text-gray-600 mb-1 block"
  }, "Pro / \u5929"), /*#__PURE__*/React.createElement("input", {
    type: "number",
    min: "1",
    max: "100",
    className: "w-full px-3 py-2 rounded-lg border border-gray-300 text-sm",
    value: proQuota,
    onChange: e => setProQuota(Number(e.target.value))
  }))), /*#__PURE__*/React.createElement("div", {
    className: "mt-3"
  }, /*#__PURE__*/React.createElement(Button, {
    variant: "primary",
    onClick: save,
    disabled: saving
  }, saving ? '保存中...' : '保存'), /*#__PURE__*/React.createElement("span", {
    className: "ml-3 text-xs text-gray-400"
  }, "\u26A0\uFE0F \u8FD0\u884C\u65F6\u751F\u6548\uFF0CWorker \u91CD\u542F\u540E\u4F1A\u6062\u590D\u9ED8\u8BA4"))));
}

// ==================== 占位页面（后续轮次填充）====================
function PlaceholderPage({
  title,
  desc
}) {
  return /*#__PURE__*/React.createElement("div", {
    className: "animate-slide-up"
  }, /*#__PURE__*/React.createElement("h1", {
    className: "text-2xl font-semibold text-gray-900 mb-2"
  }, title), /*#__PURE__*/React.createElement("p", {
    className: "text-sm text-gray-600 mb-6"
  }, desc), /*#__PURE__*/React.createElement("div", {
    className: "bg-white rounded-xl border border-gray-200 p-8 shadow-soft text-center"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-gray-400 text-sm"
  }, "\u8BE5\u9875\u9762\u5C06\u5728\u4E0B\u4E00\u8F6E\u5F00\u53D1\u4E2D\u4E0A\u7EBF")));
}

// ==================== 路由分发 ====================
function Router() {
  const {
    route
  } = useApp();
  const parts = route.split('/');
  const root = parts[0] || 'home';
  const hasId = parts.length > 1 && parts[1];
  switch (root) {
    case 'home':
      return /*#__PURE__*/React.createElement(HomePage, null);
    case 'resumes':
      return /*#__PURE__*/React.createElement(ResumesPage, null);
    case 'jds':
      return hasId ? /*#__PURE__*/React.createElement(JDDetailPage, null) : /*#__PURE__*/React.createElement(JDsPage, null);
    case 'positions':
      return hasId ? /*#__PURE__*/React.createElement(PositionDetailPage, null) : /*#__PURE__*/React.createElement(PositionsPage, null);
    case 'reviews':
      return /*#__PURE__*/React.createElement(ReviewsPage, null);
    case 'profile':
      return /*#__PURE__*/React.createElement(ProfilePage, null);
    case 'practice':
      return /*#__PURE__*/React.createElement(PracticePage, null);
    case 'suggestions':
      return /*#__PURE__*/React.createElement(SuggestionsPage, null);
    case 'wall':
      return /*#__PURE__*/React.createElement(WallPage, null);
    case 'notifications':
      return /*#__PURE__*/React.createElement(NotificationsPage, null);
    case 'settings':
      return /*#__PURE__*/React.createElement(SettingsPage, null);
    case 'admin':
      return /*#__PURE__*/React.createElement(AdminPage, null);
    default:
      return /*#__PURE__*/React.createElement(HomePage, null);
  }
}

// ==================== 加载 & 根组件 ====================
function LoadingScreen() {
  return /*#__PURE__*/React.createElement("div", {
    className: "fixed inset-0 bg-white flex flex-col items-center justify-center z-50"
  }, /*#__PURE__*/React.createElement(Logo, {
    size: 48,
    className: "animate-bounce-subtle"
  }), /*#__PURE__*/React.createElement("div", {
    className: "mt-4 text-sm text-gray-500"
  }, "\u6B63\u5728\u521D\u59CB\u5316..."));
}
function AppRoot() {
  const {
    user,
    loading
  } = useApp();
  const [showOnboarding, setShowOnboarding] = useState(() => {
    if (!user) return false;
    // v3.2: onboarding 不再强制，跳过就记 localStorage
    if (localStorage.getItem('onboarding_dismissed')) return false;
    return true;
  });

  // user 加载完成后判断
  useEffect(() => {
    if (user && !user.onboarded && !localStorage.getItem('onboarding_dismissed')) {
      setShowOnboarding(true);
    }
  }, [user]);
  if (loading) return /*#__PURE__*/React.createElement(LoadingScreen, null);
  if (!user) return /*#__PURE__*/React.createElement("div", {
    className: "fixed inset-0 bg-white flex items-center justify-center"
  }, /*#__PURE__*/React.createElement("div", {
    className: "text-center"
  }, /*#__PURE__*/React.createElement(Logo, {
    size: 48,
    className: "mx-auto"
  }), /*#__PURE__*/React.createElement("div", {
    className: "mt-4 text-sm text-gray-600"
  }, "\u8FDE\u63A5\u5931\u8D25\uFF0C\u8BF7\u5237\u65B0\u91CD\u8BD5")));
  return /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement(Layout, null, /*#__PURE__*/React.createElement(Router, null)), /*#__PURE__*/React.createElement(DeviceNoticeBubble, null), showOnboarding && /*#__PURE__*/React.createElement(OnboardingFlow, {
    onDone: () => setShowOnboarding(false)
  }));
}
function App() {
  return /*#__PURE__*/React.createElement(AppProvider, null, /*#__PURE__*/React.createElement(AppRoot, null), /*#__PURE__*/React.createElement(ToastStack, null));
}

// ==================== 挂载 ====================
const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(/*#__PURE__*/React.createElement(App, null));