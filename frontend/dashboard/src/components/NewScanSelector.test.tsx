import { render, screen } from '@testing-library/react';
import NewScanSelector from './NewScanSelector';
import { describe, it, expect, vi } from 'vitest';

describe('NewScanSelector', () => {
    it('renders scan options correctly', () => {
        const mockOnScanComplete = vi.fn();
        render(<NewScanSelector onScanComplete={mockOnScanComplete} />);

        expect(screen.getByText('Select Your Scan Strategy')).toBeInTheDocument();
        expect(screen.getByText('Static Code Audit')).toBeInTheDocument();
        expect(screen.getByText('Dynamic Attack Simulation')).toBeInTheDocument();
    });

    it('renders file upload input', () => {
        const mockOnScanComplete = vi.fn();
        render(<NewScanSelector onScanComplete={mockOnScanComplete} />);

        // Input is hidden, so we look for the label or associated text
        expect(screen.getByText('Browse Files')).toBeInTheDocument();
    });
});
