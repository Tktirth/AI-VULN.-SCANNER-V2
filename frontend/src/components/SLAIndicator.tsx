"use client";

import { useEffect, useState } from "react";

interface SLAIndicatorProps {
  deadline: string | Date;
  severity: string;
}

export default function SLAIndicator({ deadline, severity }: SLAIndicatorProps) {
  const [timeLeft, setTimeLeft] = useState<string>("");
  const [isBreached, setIsBreached] = useState<boolean>(false);

  useEffect(() => {
    const calculateTime = () => {
      const target = new Date(deadline).getTime();
      const now = new Date().getTime();
      const diff = target - now;

      if (diff <= 0) {
        setIsBreached(true);
        setTimeLeft("SLA Breached");
        return;
      }

      setIsBreached(false);
      const days = Math.floor(diff / (1000 * 60 * 60 * 24));
      const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
      const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));

      if (days > 0) {
        setTimeLeft(`${days}d ${hours}h remaining`);
      } else if (hours > 0) {
        setTimeLeft(`${hours}h ${minutes}m remaining`);
      } else {
        setTimeLeft(`${minutes}m remaining`);
      }
    };

    calculateTime();
    const timer = setInterval(calculateTime, 60000); // Update every minute
    return () => clearInterval(timer);
  }, [deadline]);

  return (
    <div
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold ${
        isBreached
          ? "bg-red-950/60 border border-red-800 text-red-200"
          : "bg-gray-800/80 border border-gray-700 text-gray-300"
      }`}
    >
      <span
        className={`w-1.5 h-1.5 rounded-full mr-1.5 ${
          isBreached ? "bg-red-500 animate-pulse" : "bg-emerald-500"
        }`}
      />
      {timeLeft}
    </div>
  );
}
