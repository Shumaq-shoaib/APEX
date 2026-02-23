import { Shield, Menu, Github } from "lucide-react";
import AppSidebar from "./AppSidebar";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet";
import { useState } from "react";

interface DashboardLayoutProps {
    children: React.ReactNode;
}

export default function DashboardLayout({ children }: DashboardLayoutProps) {
    const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

    return (
        <div className="min-h-screen bg-background text-foreground transition-colors duration-300 flex flex-col">
            {/* Header */}
            <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
                <div className="container flex h-14 items-center justify-between mx-auto px-4 md:px-6 max-w-full">
                    <div className="flex items-center gap-2">
                        <Sheet open={isMobileMenuOpen} onOpenChange={setIsMobileMenuOpen}>
                            <SheetTrigger asChild>
                                <Button variant="ghost" size="icon" className="lg:hidden mr-2">
                                    <Menu className="h-5 w-5" />
                                    <span className="sr-only">Toggle menu</span>
                                </Button>
                            </SheetTrigger>
                            <SheetContent side="left" className="p-0 w-64">
                                <AppSidebar />
                            </SheetContent>
                        </Sheet>

                        <h1 className="text-2xl font-bold bg-gradient-to-r from-primary to-green-400 bg-clip-text text-transparent">
                            APEX
                        </h1>
                        <span className="hidden md:inline-block text-sm text-muted-foreground ml-2 border-l pl-2">
                            Advanced API Security Scanner
                        </span>
                    </div>
                    <div className="flex items-center gap-4">
                        <a
                            href="https://github.com/Shumaq-shoaib/APEX"
                            target="_blank"
                            rel="noreferrer"
                            className="text-sm font-medium hover:underline underline-offset-4 flex items-center gap-2"
                            aria-label="Visit APEX GitHub repository (opens in new tab)"
                        >
                            <Github className="h-4 w-4" aria-hidden="true" />
                            <span className="hidden sm:inline">GitHub</span>
                        </a>
                        <div className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-muted/50 border">
                            <Shield className="h-4 w-4 text-primary" aria-hidden="true" />
                            <span className="text-xs font-mono font-medium">v6.8.0</span>
                        </div>
                    </div>
                </div>
            </header>

            <div className="flex flex-1 overflow-hidden">
                {/* Sidebar (Desktop) */}
                <AppSidebar />

                {/* Main Content Area */}
                <main className="flex-1 overflow-y-auto p-4 md:p-6 lg:p-8 custom-scrollbar bg-background/50">
                    <div className="mx-auto max-w-7xl animate-in fade-in slide-in-from-bottom-4 duration-500">
                        {children}
                    </div>
                    <footer className="border-t py-6 md:py-8 mt-8">
                        <div className="container flex flex-col items-center justify-between gap-4 md:h-10 md:flex-row px-4 text-center mx-auto">
                            <p className="text-sm text-muted-foreground">
                                &copy; {new Date().getFullYear()} APEX Security. Open Source API Security Testing.
                            </p>
                        </div>
                    </footer>
                </main>
            </div>
        </div>
    );
}
