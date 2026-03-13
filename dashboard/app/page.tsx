"use client";

import { useEffect, useState } from "react";

interface Stats {
  total_audits: number;
  total_findings: number;
  avg_score: number;
  severity_breakdown: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
}

interface Finding {
  id: string;
  service: string;
  issue: string;
  severity: string;
  banner: string;
  timestamp: string;
}

interface Audit {
  meta: {
    target: string;
    generated_at: string;
    total_findings: number;
    risk_score: number;
    risk_level: string;
    version: string;
  };
  findings: Finding[];
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "text-red-900 bg-red-200",
  HIGH: "text-red-600 bg-red-100",
  MEDIUM: "text-orange-600 bg-orange-100",
  LOW: "text-green-600 bg-green-100",
};

const LEVEL_COLORS: Record<string, string> = {
  CRITICAL: "text-red-900",
  HIGH: "text-red-500",
  MEDIUM: "text-orange-500",
  LOW: "text-green-500",
};

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [audits, setAudits] = useState<Audit[]>([]);
  const [selected, setSelected] = useState<Audit | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statsRes, auditsRes] = await Promise.all([
          fetch("http://127.0.0.1:5000/api/stats"),
          fetch("http://127.0.0.1:5000/api/audits"),
        ]);
        setStats(await statsRes.json());
        const data: Audit[] = await auditsRes.json();
        data.sort(
          (a, b) =>
            new Date(b.meta.generated_at).getTime() -
            new Date(a.meta.generated_at).getTime()
        );
        setAudits(data);
      } catch {
        setError("Impossible de contacter l'API. Lance : py src/api.py");
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  if (loading)
    return (
      <div className="flex items-center justify-center h-screen bg-gray-950 text-cyan-400 text-xl">
        Chargement...
      </div>
    );
  if (error)
    return (
      <div className="flex items-center justify-center h-screen bg-gray-950 text-red-400 text-xl">
        {error}
      </div>
    );

  return (
    <main className="min-h-screen bg-gray-950 text-gray-200 p-6">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-cyan-400">GuardianPy Dashboard</h1>
        <p className="text-gray-400 mt-1">Tableau de bord des audits de sécurité</p>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          <StatCard label="Audits" value={stats.total_audits} />
          <StatCard label="Findings" value={stats.total_findings} />
          <StatCard label="Score moyen" value={`${stats.avg_score}/100`} />
          <div className="bg-gray-900 rounded-xl p-4 border border-gray-800">
            <p className="text-gray-400 text-sm mb-2">Sévérités</p>
            <div className="flex flex-col gap-1 text-sm">
              {Object.entries(stats.severity_breakdown).map(([sev, count]) => (
                <span
                  key={sev}
                  className={`px-2 py-0.5 rounded font-medium ${SEVERITY_COLORS[sev]}`}
                >
                  {sev} : {count}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Liste des audits */}
        <div className="lg:col-span-1">
          <h2 className="text-lg font-semibold text-gray-300 mb-3">Audits récents</h2>
          <div className="flex flex-col gap-2">
            {audits.map((audit, i) => (
              <button
                key={i}
                onClick={() => setSelected(audit)}
                className={`text-left bg-gray-900 border rounded-xl p-4 hover:border-cyan-500 transition-colors ${
                  selected === audit ? "border-cyan-500" : "border-gray-800"
                }`}
              >
                <div className="flex justify-between items-center">
                  <span className="font-medium text-cyan-300">{audit.meta.target}</span>
                  <span className={`text-sm font-bold ${LEVEL_COLORS[audit.meta.risk_level]}`}>
                    {audit.meta.risk_score}/100
                  </span>
                </div>
                <p className="text-gray-500 text-xs mt-1">
                  {new Date(audit.meta.generated_at).toLocaleString("fr-FR")}
                </p>
                <p className="text-gray-400 text-xs">{audit.meta.total_findings} finding(s)</p>
              </button>
            ))}
          </div>
        </div>

        {/* Détail de l'audit sélectionné */}
        <div className="lg:col-span-2">
          <h2 className="text-lg font-semibold text-gray-300 mb-3">Détail</h2>
          {selected ? (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <div className="flex justify-between items-start mb-4">
                <div>
                  <h3 className="text-xl font-bold text-cyan-400">{selected.meta.target}</h3>
                  <p className="text-gray-400 text-sm">
                    {new Date(selected.meta.generated_at).toLocaleString("fr-FR")}
                  </p>
                </div>
                <span className={`text-2xl font-bold ${LEVEL_COLORS[selected.meta.risk_level]}`}>
                  {selected.meta.risk_score}/100 — {selected.meta.risk_level}
                </span>
              </div>
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-gray-400 text-left border-b border-gray-800">
                    <th className="pb-2">ID</th>
                    <th className="pb-2">Service</th>
                    <th className="pb-2">Problème</th>
                    <th className="pb-2">Sévérité</th>
                    <th className="pb-2">Bannière</th>
                  </tr>
                </thead>
                <tbody>
                  {selected.findings.map((f, i) => (
                    <tr key={i} className="border-b border-gray-800">
                      <td className="py-2 text-gray-400">{f.id}</td>
                      <td className="py-2">{f.service}</td>
                      <td className="py-2">{f.issue}</td>
                      <td className="py-2">
                        <span
                          className={`px-2 py-0.5 rounded text-xs font-bold ${SEVERITY_COLORS[f.severity]}`}
                        >
                          {f.severity}
                        </span>
                      </td>
                      <td className="py-2 text-xs text-gray-400 font-mono truncate max-w-[150px]">
                        {f.banner}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 text-gray-500 text-center">
              Sélectionne un audit pour voir le détail
            </div>
          )}
        </div>
      </div>
    </main>
  );
}

function StatCard({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="bg-gray-900 rounded-xl p-4 border border-gray-800">
      <p className="text-gray-400 text-sm">{label}</p>
      <p className="text-2xl font-bold text-cyan-400 mt-1">{value}</p>
    </div>
  );
}
