-- Track a host reset request separately from a DPU reprovision request. A
-- reset (mh reset from a non-ready state) is not a reprovision, so it gets its
-- own per-DPU marker instead of overloading reprovisioning_requested.

ALTER TABLE machines
    ADD COLUMN reset_requested JSONB;
