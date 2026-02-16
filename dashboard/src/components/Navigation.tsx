"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";

const mainNavItems = [
  { href: "/", label: "Overview" },
  { href: "/network", label: "Network" },
  { href: "/mining", label: "Mining" },
];

const ghostPayItems = [
  { href: "/wraith", label: "Wraith" },
  { href: "/locks", label: "Locks" },
  { href: "/payments", label: "Payments" },
  { href: "/settlement", label: "Settlement" },
];

const operatorItems = [
  { href: "/swarm", label: "Swarm" },
  { href: "/rewards", label: "Rewards" },
  { href: "/migration", label: "Migration" },
];

const settingsItems = [
  { href: "/config", label: "Configuration" },
  { href: "/logs", label: "Logs" },
];

export function Navigation() {
  const pathname = usePathname();
  const [ghostPayOpen, setGhostPayOpen] = useState(false);
  const [operatorOpen, setOperatorOpen] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const isGhostPayActive = ghostPayItems.some((item) => pathname === item.href);
  const isOperatorActive = operatorItems.some((item) => pathname === item.href);


  return (
    <nav className="border-b border-gray-800 bg-gray-900/50 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-14">
          <div className="flex items-center gap-6">
            <Link href="/" className="flex items-center gap-2">
              <span className="text-lg font-semibold text-gray-100">
                Ghost Node
              </span>
            </Link>

            {/* Desktop Navigation */}
            <div className="hidden lg:flex gap-1">
              {/* Main Nav */}
              {mainNavItems.map((item) => {
                const isActive = pathname === item.href;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                      isActive
                        ? "bg-gray-800 text-white"
                        : "text-gray-400 hover:text-gray-100 hover:bg-gray-800/50"
                    }`}
                  >
                    {item.label}
                  </Link>
                );
              })}

              {/* Ghost Pay Dropdown */}
              <div className="relative">
                <button
                  onClick={() => setGhostPayOpen(!ghostPayOpen)}
                  onBlur={() => setTimeout(() => setGhostPayOpen(false), 150)}
                  className={`px-3 py-2 rounded-md text-sm font-medium transition-colors flex items-center gap-1 ${
                    isGhostPayActive
                      ? "bg-purple-900/50 text-purple-300"
                      : "text-gray-400 hover:text-gray-100 hover:bg-gray-800/50"
                  }`}
                >
                  Ghost Pay
                  <svg
                    className={`w-4 h-4 transition-transform ${ghostPayOpen ? "rotate-180" : ""}`}
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </button>

                {ghostPayOpen && (
                  <div className="absolute top-full left-0 mt-1 w-40 bg-gray-900 border border-gray-800 rounded-lg shadow-lg py-1 z-50">
                    {ghostPayItems.map((item) => {
                      const isActive = pathname === item.href;
                      return (
                        <Link
                          key={item.href}
                          href={item.href}
                          className={`block px-4 py-2 text-sm ${
                            isActive
                              ? "bg-purple-900/30 text-purple-300"
                              : "text-gray-400 hover:text-gray-100 hover:bg-gray-800"
                          }`}
                        >
                          {item.label}
                        </Link>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Operator Dropdown */}
              <div className="relative">
                <button
                  onClick={() => setOperatorOpen(!operatorOpen)}
                  onBlur={() => setTimeout(() => setOperatorOpen(false), 150)}
                  className={`px-3 py-2 rounded-md text-sm font-medium transition-colors flex items-center gap-1 ${
                    isOperatorActive
                      ? "bg-blue-900/50 text-blue-300"
                      : "text-gray-400 hover:text-gray-100 hover:bg-gray-800/50"
                  }`}
                >
                  Operator
                  <svg
                    className={`w-4 h-4 transition-transform ${operatorOpen ? "rotate-180" : ""}`}
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </button>

                {operatorOpen && (
                  <div className="absolute top-full left-0 mt-1 w-40 bg-gray-900 border border-gray-800 rounded-lg shadow-lg py-1 z-50">
                    {operatorItems.map((item) => {
                      const isActive = pathname === item.href;
                      return (
                        <Link
                          key={item.href}
                          href={item.href}
                          className={`block px-4 py-2 text-sm ${
                            isActive
                              ? "bg-blue-900/30 text-blue-300"
                              : "text-gray-400 hover:text-gray-100 hover:bg-gray-800"
                          }`}
                        >
                          {item.label}
                        </Link>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Settings Nav */}
              {settingsItems.map((item) => {
                const isActive = pathname === item.href;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                      isActive
                        ? "bg-gray-800 text-white"
                        : "text-gray-400 hover:text-gray-100 hover:bg-gray-800/50"
                    }`}
                  >
                    {item.label}
                  </Link>
                );
              })}
            </div>
          </div>

          <div className="flex items-center gap-4">
            <span className="hidden sm:inline text-xs text-gray-500">
              <code>{process.env.NEXT_PUBLIC_API_URL?.replace('http://', '') || '127.0.0.1:8080'}</code>
            </span>

            {/* Mobile menu button */}
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="lg:hidden p-2 text-gray-400 hover:text-gray-100"
              aria-label="Toggle menu"
            >
              {mobileMenuOpen ? (
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              ) : (
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                </svg>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Navigation */}
      {mobileMenuOpen && (
        <div className="lg:hidden border-t border-gray-800 bg-gray-900">
          <div className="px-4 py-2 space-y-1">
            {/* Main Items */}
            {mainNavItems.map((item) => {
              const isActive = pathname === item.href;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  onClick={() => setMobileMenuOpen(false)}
                  className={`block px-3 py-2 rounded-md text-sm font-medium ${
                    isActive
                      ? "bg-gray-800 text-white"
                      : "text-gray-400 hover:text-gray-100 hover:bg-gray-800/50"
                  }`}
                >
                  {item.label}
                </Link>
              );
            })}

            {/* Ghost Pay Section */}
            <div className="pt-2 border-t border-gray-800">
              <div className="px-3 py-1 text-xs text-purple-400 font-medium">Ghost Pay</div>
              {ghostPayItems.map((item) => {
                const isActive = pathname === item.href;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    onClick={() => setMobileMenuOpen(false)}
                    className={`block px-3 py-2 rounded-md text-sm font-medium ${
                      isActive
                        ? "bg-purple-900/30 text-purple-300"
                        : "text-gray-400 hover:text-gray-100 hover:bg-gray-800/50"
                    }`}
                  >
                    {item.label}
                  </Link>
                );
              })}
            </div>

            {/* Operator Section */}
            <div className="pt-2 border-t border-gray-800">
              <div className="px-3 py-1 text-xs text-blue-400 font-medium">Operator</div>
              {operatorItems.map((item) => {
                const isActive = pathname === item.href;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    onClick={() => setMobileMenuOpen(false)}
                    className={`block px-3 py-2 rounded-md text-sm font-medium ${
                      isActive
                        ? "bg-blue-900/30 text-blue-300"
                        : "text-gray-400 hover:text-gray-100 hover:bg-gray-800/50"
                    }`}
                  >
                    {item.label}
                  </Link>
                );
              })}
            </div>

            {/* Settings Section */}
            <div className="pt-2 border-t border-gray-800">
              <div className="px-3 py-1 text-xs text-gray-500 font-medium">Settings</div>
              {settingsItems.map((item) => {
                const isActive = pathname === item.href;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    onClick={() => setMobileMenuOpen(false)}
                    className={`block px-3 py-2 rounded-md text-sm font-medium ${
                      isActive
                        ? "bg-gray-800 text-white"
                        : "text-gray-400 hover:text-gray-100 hover:bg-gray-800/50"
                    }`}
                  >
                    {item.label}
                  </Link>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </nav>
  );
}
