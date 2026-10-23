import React, { useEffect, useRef } from 'react';

/**
 * ForensicGlobeCanvas
 * Restores the authentic ARGUS 3D-projected forensic particle network globe
 * (750 nodes, rotating spherical projection, interconnected lines, and crimson threat nodes).
 */
export default function ForensicGlobeCanvas({
  theme = 'dark',
  nodeColor = null,
  lineColor = null,
  threatColor = null,
  centerXRatio = 0.35,
  centerYRatio = 0.52,
  radiusRatio = 0.46,
  pointCount = 1400,
  className = ''
}) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };
    window.addEventListener('resize', handleResize);

    // Generate 3D sphere points using Fibonacci sphere distribution
    const POINT_COUNT = pointCount;
    const RADIUS = Math.min(width, height) * radiusRatio;
    const points = [];

    for (let i = 0; i < POINT_COUNT; i++) {
      const phi = Math.acos(-1 + (2 * i) / POINT_COUNT);
      const theta = Math.sqrt(POINT_COUNT * Math.PI) * phi;
      points.push({
        x: RADIUS * Math.cos(theta) * Math.sin(phi),
        y: RADIUS * Math.sin(theta) * Math.sin(phi),
        z: RADIUS * Math.cos(phi),
        isThreat: i % 18 === 0,
        pulse: Math.random() * Math.PI
      });
    }

    let rotX = 0.3;
    let rotY = -0.5;
    let isDragging = false;
    let lastMouseX = 0;
    let lastMouseY = 0;
    let frameId;

    const handleMouseDown = (e) => {
      // Don't drag if clicking inside cards or inputs
      if (e.target.closest('form') || e.target.closest('button') || e.target.closest('input') || e.target.closest('header')) return;
      isDragging = true;
      lastMouseX = e.clientX;
      lastMouseY = e.clientY;
    };

    const handleMouseMove = (e) => {
      if (!isDragging) return;
      const dx = e.clientX - lastMouseX;
      const dy = e.clientY - lastMouseY;
      rotY += dx * 0.004;
      rotX += dy * 0.004;
      lastMouseX = e.clientX;
      lastMouseY = e.clientY;
    };

    const handleMouseUp = () => {
      isDragging = false;
    };

    window.addEventListener('mousedown', handleMouseDown);
    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', handleMouseUp);

    function renderGlobe() {
      ctx.clearRect(0, 0, width, height);

      // Smooth auto-rotation
      if (!isDragging) {
        rotY += 0.0022;
        rotX += 0.0004;
      }

      // Responsive center calculation
      const isMobile = width <= 1024;
      const effectiveCenterXRatio = isMobile ? 0.5 : centerXRatio;
      const centerX = width * effectiveCenterXRatio;
      const centerY = height * centerYRatio;

      const cosX = Math.cos(rotX);
      const sinX = Math.sin(rotX);
      const cosY = Math.cos(rotY);
      const sinY = Math.sin(rotY);

      const projected = [];

      for (let i = 0; i < points.length; i++) {
        const p = points[i];
        p.pulse += 0.035;

        // 3D Matrix Rotation (Y then X)
        const x1 = p.x * cosY - p.z * sinY;
        const z1 = p.z * cosY + p.x * sinY;
        const y2 = p.y * cosX - z1 * sinX;
        const z2 = z1 * cosX + p.y * sinX;

        // Perspective projection
        const fov = 820;
        const scale = fov / (fov + z2 + 100);
        const x2D = centerX + x1 * scale;
        const y2D = centerY + y2 * scale;

        projected.push({
          x: x2D,
          y: y2D,
          z: z2,
          scale,
          isThreat: p.isThreat,
          pulse: p.pulse
        });
      }

      // Depth sorting for accurate 3D occlusions
      projected.sort((a, b) => b.z - a.z);

      const isDark = (document.documentElement.getAttribute('data-theme') || theme) !== 'light';


      ctx.lineWidth = 0.8;

      // Draw interconnected network lines
      for (let i = 0; i < projected.length; i += 2) {
        for (let j = i + 1; j < Math.min(i + 7, projected.length); j++) {
          const p1 = projected[i];
          const p2 = projected[j];
          const dist = Math.hypot(p1.x - p2.x, p1.y - p2.y);

          if (dist < 65 && (p1.z > -RADIUS * 0.45 || p2.z > -RADIUS * 0.45)) {
            const distRatio = 1 - dist / 65;
            const depthFactor = Math.max(0.25, (Math.max(p1.z, p2.z) + RADIUS) / (2 * RADIUS));
            const alpha = Math.min(0.65, Math.max(0, distRatio * 0.45 * depthFactor));

            if (p1.isThreat || p2.isThreat) {
              ctx.strokeStyle = threatColor 
                ? `${threatColor}${Math.round(alpha * 255).toString(16).padStart(2, '0')}`
                : (isDark ? `rgba(239, 68, 68, ${alpha * 1.6})` : `rgba(220, 38, 38, ${alpha * 1.5})`);
            } else if (lineColor) {
              ctx.strokeStyle = `${lineColor}${Math.round(alpha * 255).toString(16).padStart(2, '0')}`;
            } else {
              ctx.strokeStyle = isDark
                ? `rgba(56, 189, 248, ${alpha})`
                : `rgba(37, 99, 235, ${alpha * 0.95})`;
            }

            ctx.beginPath();
            ctx.moveTo(p1.x, p1.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.stroke();
          }
        }
      }

      // Draw particle nodes & pulsing crimson threat nodes
      for (let i = 0; i < projected.length; i++) {
        const p = projected[i];
        if (p.z < -RADIUS * 0.95) continue;

        const depthFactor = Math.max(0, Math.min(1, (p.z + RADIUS) / (2 * RADIUS)));
        const size = (p.isThreat ? 3.4 : (p.z > 0 ? 2.4 : 1.7)) * p.scale;
        const alpha = Math.min(1, Math.max(0.22, 0.22 + depthFactor * 0.78));

        if (p.isThreat) {
          const ringProgress = (p.pulse % Math.PI) / Math.PI;
          const ringRadius = size + ringProgress * 10;
          const ringAlpha = (1 - ringProgress) * 0.75;

          ctx.lineWidth = 1;
          ctx.strokeStyle = threatColor || (isDark ? `rgba(239, 68, 68, ${ringAlpha})` : `rgba(220, 38, 38, ${ringAlpha})`);
          ctx.beginPath();
          ctx.arc(p.x, p.y, ringRadius, 0, Math.PI * 2);
          ctx.stroke();

          ctx.fillStyle = threatColor || (isDark ? '#ff3b30' : '#dc2626');
          ctx.beginPath();
          ctx.arc(p.x, p.y, size, 0, Math.PI * 2);
          ctx.fill();
        } else {
          if (nodeColor) {
            ctx.fillStyle = nodeColor;
          } else if (isDark) {
            if (p.z > RADIUS * 0.35) {
              ctx.fillStyle = '#ffffff';
            } else if (p.z > 0) {
              ctx.fillStyle = '#38bdf8';
            } else if (p.z > -RADIUS * 0.45) {
              ctx.fillStyle = '#0284c7';
            } else {
              ctx.fillStyle = '#1e40af';
            }
          } else {
            if (p.z > RADIUS * 0.35) {
              ctx.fillStyle = '#1e3a8a';
            } else if (p.z > 0) {
              ctx.fillStyle = '#2563eb';
            } else if (p.z > -RADIUS * 0.45) {
              ctx.fillStyle = '#3b82f6';
            } else {
              ctx.fillStyle = '#93c5fd';
            }
          }
          ctx.beginPath();
          ctx.arc(p.x, p.y, size, 0, Math.PI * 2);
          ctx.fill();
        }
      }

      frameId = requestAnimationFrame(renderGlobe);
    }

    renderGlobe();

    return () => {
      cancelAnimationFrame(frameId);
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('mousedown', handleMouseDown);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    };
  }, [theme, nodeColor, lineColor, threatColor, centerXRatio, centerYRatio, radiusRatio, pointCount]);

  return (
    <canvas 
      ref={canvasRef} 
      className={`forensic-globe-canvas ${className}`}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 0,
        pointerEvents: 'auto',
        cursor: 'grab'
      }} 
    />
  );
}
