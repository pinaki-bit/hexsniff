import { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, useLocation } from 'react-router-dom';
import { Sidebar } from './components/layout/Sidebar';
import { TopBar } from './components/layout/TopBar';
import { StatusBar } from './components/layout/StatusBar';
import { BootSequence } from './components/BootSequence';
import { AICopilot } from './components/AICopilot';
import { Dashboard } from './pages/Dashboard';
import { PacketAnalyzer } from './pages/PacketAnalyzer';
import { ThreatMap } from './pages/ThreatMap';
import { AIAnalyst } from './pages/AIAnalyst';
import { NetworkTopology } from './pages/NetworkTopology';
import { ProtocolAnalytics } from './pages/ProtocolAnalytics';
import { ThreatIntelligence } from './pages/ThreatIntelligence';
import { AssetInventory } from './pages/AssetInventory';
import { Investigation } from './pages/Investigation';
import { DetectionValidationLab } from './pages/DetectionValidationLab';
import { DetectionEngineering } from './pages/DetectionEngineering';
import { ThreatHunting } from './pages/ThreatHunting';
import { CaseManagement } from './pages/CaseManagement';
import { Reports } from './pages/Reports';
import { store } from './store';
import { LazyMotion, domAnimation, AnimatePresence, m } from 'framer-motion';
import { BackgroundEffects } from './components/Visuals/BackgroundEffects';

function RouteTransition() {
  const location = useLocation();
  return (
    <AnimatePresence mode="wait">
      <Routes location={location} key={location.pathname}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/analyzer" element={<PacketAnalyzer />} />
        <Route path="/map" element={<ThreatMap />} />
        <Route path="/ai" element={<AIAnalyst />} />
        <Route path="/topology" element={<NetworkTopology />} />
        <Route path="/analytics" element={<ProtocolAnalytics />} />
        <Route path="/intel" element={<ThreatIntelligence />} />
        <Route path="/assets" element={<AssetInventory />} />
        <Route path="/hunt" element={<ThreatHunting />} />
        <Route path="/investigate" element={<Investigation />} />
        <Route path="/validation" element={<DetectionValidationLab />} />
        <Route path="/engineering" element={<DetectionEngineering />} />
        <Route path="/cases" element={<CaseManagement />} />
        <Route path="/reports" element={<Reports />} />
      </Routes>
    </AnimatePresence>
  );
}

function App() {
  const [booted, setBooted] = useState(false);

  useEffect(() => {
    store.fetchInterfaces();
    store.connectWS();
  }, []);

  return (
    <LazyMotion features={domAnimation}>
      <AnimatePresence mode="wait">
        {!booted && <BootSequence key="boot" onComplete={() => setBooted(true)} />}
      </AnimatePresence>

      <BrowserRouter>
        <m.div 
          initial={{ opacity: 0 }}
          animate={{ opacity: booted ? 1 : 0 }}
          transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
          className="flex h-screen w-screen overflow-hidden bg-void text-text-main font-sans antialiased selection:bg-neon-blue selection:text-void"
        >
          <BackgroundEffects />

          <Sidebar />
          
          <div className="flex flex-col flex-1 min-w-0 z-10 relative h-full pl-2 bg-surface/30">
            <TopBar />
            
            <main className="flex-1 overflow-hidden relative">
              <div className="absolute inset-0 overflow-y-auto custom-scrollbar p-6 lg:p-8">
                <RouteTransition />
              </div>
            </main>
            
            <StatusBar />
          </div>
          
          <AICopilot />
        </m.div>
      </BrowserRouter>
    </LazyMotion>
  );
}

export default App;
