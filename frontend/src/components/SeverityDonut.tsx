"use client";

interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface SeverityDonutProps {
  counts: SeverityCounts;
}

export default function SeverityDonut({ counts }: SeverityDonutProps) {
  const { critical, high, medium, low } = counts;
  const total = critical + high + medium + low;

  const radius = 50;
  const circumference = 2 * Math.PI * radius;

  // Calculate stroke dash offsets for each slice
  const items = [
    { value: critical, color: "#EF4444", label: "Critical" },
    { value: high, color: "#F97316", label: "High" },
    { value: medium, color: "#EAB308", label: "Medium" },
    { value: low, color: "#22C55E", label: "Low" },
  ];

  let accumulatedPercentage = 0;

  const slices = items
    .filter((item) => item.value > 0)
    .map((item) => {
      const percentage = (item.value / total) * 100;
      const strokeDashoffset = circumference - (circumference * percentage) / 100;
      const rotation = (accumulatedPercentage / 100) * 360;
      accumulatedPercentage += percentage;

      return {
        ...item,
        percentage,
        strokeDashoffset,
        rotation,
      };
    });

  return (
    <div className="flex flex-col items-center justify-center p-4">
      <div className="relative w-48 h-48">
        {total === 0 ? (
          <div className="absolute inset-0 flex items-center justify-center rounded-full border-4 border-dashed border-gray-800 text-gray-500 text-sm">
            No Findings
          </div>
        ) : (
          <>
            <svg viewBox="0 0 120 120" className="w-full h-full transform -rotate-90">
              <circle
                cx="60"
                cy="60"
                r={radius}
                fill="transparent"
                stroke="#1f2937"
                strokeWidth="12"
              />
              {slices.map((slice, index) => (
                <circle
                  key={index}
                  cx="60"
                  cy="60"
                  r={radius}
                  fill="transparent"
                  stroke={slice.color}
                  strokeWidth="12"
                  strokeDasharray={circumference}
                  strokeDashoffset={slice.strokeDashoffset}
                  transform={`rotate(${slice.rotation} 60 60)`}
                  strokeLinecap="round"
                  className="transition-all duration-1000 ease-out"
                />
              ))}
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-4xl font-extrabold text-white tracking-tight">{total}</span>
              <span className="text-xs uppercase tracking-wider text-gray-400 font-semibold mt-1">
                Total
              </span>
            </div>
          </>
        )}
      </div>

      <div className="grid grid-cols-2 gap-x-6 gap-y-2 mt-6 w-full max-w-xs">
        {items.map((item) => (
          <div key={item.label} className="flex items-center space-x-2.5">
            <span
              className="w-3 h-3 rounded-full flex-shrink-0"
              style={{ backgroundColor: item.color }}
            />
            <span className="text-gray-300 text-sm">{item.label}</span>
            <span className="text-white font-bold ml-auto">{item.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
