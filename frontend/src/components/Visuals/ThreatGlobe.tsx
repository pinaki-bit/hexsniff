import { useRef, useMemo } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { OrbitControls, Stars, Line } from '@react-three/drei';
import * as THREE from 'three';

// Generates arc paths between two points on a sphere
function getArcLines(start: THREE.Vector3, end: THREE.Vector3, numPoints = 20) {
  const distance = start.distanceTo(end);
  const midPoint = start.clone().add(end).multiplyScalar(0.5);
  // Bulge out the midpoint based on distance
  midPoint.normalize().multiplyScalar(1 + distance * 0.3);
  
  const curve = new THREE.QuadraticBezierCurve3(start, midPoint, end);
  return curve.getPoints(numPoints);
}

// Convert Lat/Lon to Vector3 on a sphere of radius R
function latLonToVector3(lat: number, lon: number, radius = 1) {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lon + 180) * (Math.PI / 180);

  const x = -(radius * Math.sin(phi) * Math.cos(theta));
  const z = (radius * Math.sin(phi) * Math.sin(theta));
  const y = (radius * Math.cos(phi));

  return new THREE.Vector3(x, y, z);
}

function Connections({ packets, isHighAlert }: { packets: any[], isHighAlert: boolean }) {
  const arcs = useMemo(() => {
    // We mock lat/lon for the visualization based on IPs to make it dynamic
    return packets.slice(0, 30).map((p) => {
      // Deterministic pseudo-random lat/lon based on IP strings
      const srcHash = p.src_ip.split('.').reduce((a: number, b: string) => a + parseInt(b), 0);
      const dstHash = p.dst_ip.split('.').reduce((a: number, b: string) => a + parseInt(b), 0);
      
      const startLat = (srcHash % 180) - 90;
      const startLon = ((srcHash * 7) % 360) - 180;
      
      const endLat = (dstHash % 180) - 90;
      const endLon = ((dstHash * 7) % 360) - 180;

      const start = latLonToVector3(startLat, startLon, 2);
      const end = latLonToVector3(endLat, endLon, 2);
      
      const points = getArcLines(start, end);
      const isThreat = (p.alerts && p.alerts.length > 0);
      
      return {
        points,
        color: isThreat || isHighAlert ? '#FF2A55' : '#00F0FF',
        opacity: isThreat ? 0.8 : 0.4
      };
    });
  }, [packets, isHighAlert]);

  return (
    <group>
      {arcs.map((arc, idx) => (
        <Line 
          key={idx} 
          points={arc.points} 
          color={arc.color} 
          lineWidth={1.5} 
          transparent 
          opacity={arc.opacity} 
        />
      ))}
    </group>
  );
}

function Globe({ isHighAlert }: { isHighAlert: boolean }) {
  const meshRef = useRef<THREE.Mesh>(null);

  useFrame(({ clock }) => {
    if (meshRef.current) {
      meshRef.current.rotation.y = clock.getElapsedTime() * 0.05;
    }
  });

  return (
    <group ref={meshRef}>
      {/* Core Sphere */}
      <mesh>
        <sphereGeometry args={[1.98, 64, 64]} />
        <meshBasicMaterial color="#030712" transparent opacity={0.9} />
      </mesh>
      
      {/* Wireframe Grid */}
      <mesh>
        <sphereGeometry args={[2, 32, 32]} />
        <meshBasicMaterial 
          color={isHighAlert ? "#FF2A55" : "#00F0FF"} 
          wireframe 
          transparent 
          opacity={0.15} 
        />
      </mesh>
    </group>
  );
}

export function ThreatGlobe({ isHighAlert = false, packets = [] }: { isHighAlert?: boolean, packets?: any[] }) {
  return (
    <div className="absolute inset-0 z-0">
      <Canvas camera={{ position: [0, 0, 5], fov: 45 }}>
        <ambientLight intensity={0.5} />
        <Stars radius={100} depth={50} count={3000} factor={4} saturation={0} fade speed={1} />
        <Globe isHighAlert={isHighAlert} />
        <Connections packets={packets} isHighAlert={isHighAlert} />
        <OrbitControls 
          enableZoom={false} 
          enablePan={false} 
          autoRotate 
          autoRotateSpeed={0.5} 
          maxPolarAngle={Math.PI / 1.5}
          minPolarAngle={Math.PI / 3}
        />
      </Canvas>
    </div>
  );
}
