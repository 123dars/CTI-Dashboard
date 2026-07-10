import React from 'react';
import { ComposableMap, Geographies, Geography, Marker } from 'react-simple-maps';
import { Globe } from 'lucide-react';

const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

export default function ThreatMap({ threats }) {
  const markers = (threats || []).filter(t => t.lat != null && t.lon != null).map(t => ({
    name: t.indicator,
    coordinates: [Number(t.lon), Number(t.lat)],
    severity: t.severity
  }));

  const getColor = (severity) => {
    switch(severity) {
      case 'CRITICAL': return '#ef4444'; // Red
      case 'HIGH': return '#f59e0b'; // Orange
      case 'MEDIUM': return '#eab308'; // Yellow
      case 'LOW': return '#22c55e'; // Green
      default: return '#3b82f6'; // Blue
    }
  };

  return (
    <div className="glass-panel p-5 rounded-xl h-full flex flex-col">
      <h3 className="text-lg font-semibold mb-4 flex items-center">
        <Globe size={18} className="mr-2 text-blue-400" /> Global Threat Map
      </h3>
      <div className="flex-1 min-h-[300px] w-full bg-slate-900/50 rounded-lg overflow-hidden border border-slate-700 flex items-center justify-center">
        <ComposableMap projectionConfig={{ scale: 140 }}>
          <Geographies geography={geoUrl}>
            {({ geographies }) =>
              geographies ? geographies.map((geo) => (
                <Geography
                  key={geo.rsmKey}
                  geography={geo}
                  fill="#1e293b"
                  stroke="#334155"
                  strokeWidth={0.5}
                  style={{
                    default: { outline: 'none' },
                    hover: { fill: '#334155', outline: 'none' },
                    pressed: { outline: 'none' },
                  }}
                />
              )) : null
            }
          </Geographies>
          {markers.map(({ name, coordinates, severity }, i) => (
            <Marker key={i} coordinates={coordinates}>
              <circle r={3} fill={getColor(severity)} stroke="#fff" strokeWidth={0.5} />
            </Marker>
          ))}
        </ComposableMap>
      </div>
    </div>
  );
}
