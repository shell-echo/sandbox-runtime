ALTER TABLE sandbox_runtime_product.product_operation_attempts
    DROP CONSTRAINT product_operation_attempts_provider_action,
    ADD CONSTRAINT product_operation_attempts_provider_action CHECK (
        provider_action IS NULL OR provider_action IN (
            'create', 'suspend', 'resume', 'terminate',
            'open_runtime_session', 'close_runtime_session',
            'open_browser_session', 'terminate_browser_session',
            'open_desktop_session', 'close_desktop_session'
        )
    );
