import { ReactNode } from "react";

type BadgeVariant = "success" | "warning" | "error" | "info" | "default";

interface BadgeProps {
  children: ReactNode;
  variant?: BadgeVariant;
  className?: string;
}

const variants: Record<BadgeVariant, string> = {
  success: "bg-green-900 text-green-300 border-green-700",
  warning: "bg-orange-900 text-orange-300 border-orange-700",
  error: "bg-red-900 text-red-300 border-red-700",
  info: "bg-blue-900 text-blue-300 border-blue-700",
  default: "bg-gray-800 text-gray-300 border-gray-700",
};

export function Badge({ children, variant = "default", className = "" }: BadgeProps) {
  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${variants[variant]} ${className}`}
    >
      {children}
    </span>
  );
}
