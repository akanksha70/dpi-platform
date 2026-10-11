CREATE TABLE analysis_job (
    id          VARCHAR(36)   PRIMARY KEY,
    file_name   VARCHAR(255)  NOT NULL,
    status      VARCHAR(20)   NOT NULL,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL,
    started_at  TIMESTAMP WITH TIME ZONE,
    finished_at TIMESTAMP WITH TIME ZONE,
    error       VARCHAR(1000),
    rules_json  VARCHAR(100000) NOT NULL,
    report_json VARCHAR(1000000),
    CONSTRAINT ck_analysis_job_status CHECK (status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED'))
);

CREATE INDEX idx_analysis_job_created_at ON analysis_job (created_at);
CREATE INDEX idx_analysis_job_status ON analysis_job (status);