import { Component, ErrorInfo, ReactNode } from "react";
import { AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";

interface Props {
    children?: ReactNode;
}

interface State {
    hasError: boolean;
    error: Error | null;
}

export default class ErrorBoundary extends Component<Props, State> {
    public state: State = {
        hasError: false,
        error: null,
    };

    public static getDerivedStateFromError(error: Error): State {
        return { hasError: true, error };
    }

    public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
        console.error("Uncaught error:", error, errorInfo);
    }

    public render() {
        if (this.state.hasError) {
            return (
                <div className="min-h-screen flex items-center justify-center bg-slate-50 p-4">
                    <div className="max-w-md w-full bg-white border border-red-200 rounded-lg shadow-lg p-6 text-center space-y-4">
                        <div className="bg-red-100 p-3 rounded-full inline-flex items-center justify-center">
                            <AlertCircle className="h-8 w-8 text-red-600" />
                        </div>
                        <h1 className="text-2xl font-bold text-slate-800">Something went wrong</h1>
                        <p className="text-slate-600 text-sm">
                            An unexpected error occurred in the application.
                        </p>
                        {this.state.error && (
                            <pre className="mt-4 p-3 bg-slate-100 rounded text-left text-xs font-mono overflow-auto max-h-32 text-red-700">
                                {this.state.error.toString()}
                            </pre>
                        )}
                        <div className="pt-2">
                            <Button
                                onClick={() => window.location.reload()}
                                className="w-full bg-slate-900 hover:bg-slate-800"
                            >
                                Reload Application
                            </Button>
                        </div>
                    </div>
                </div>
            );
        }

        return this.props.children;
    }
}
