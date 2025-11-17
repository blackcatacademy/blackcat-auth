<?php
declare(strict_types=1);

namespace BlackCat\Auth\Session;

final class PdoSessionStore implements SessionStoreInterface
{
    private bool $initialized = false;

    public function __construct(
        private readonly \PDO $pdo,
        private readonly string $table = 'auth_sessions',
    ) {}

    public function save(SessionRecord $session): void
    {
        $this->ensureTable();
        $this->pdo->beginTransaction();
        $delete = $this->pdo->prepare(sprintf('DELETE FROM %s WHERE id = :id', $this->table));
        $delete->execute(['id' => $session->id]);
        $insert = $this->pdo->prepare(sprintf(
            'INSERT INTO %s (id, subject, issued_at, expires_at, claims, context) VALUES (:id, :subject, :issued_at, :expires_at, :claims, :context)',
            $this->table
        ));
        $insert->execute([
            'id' => $session->id,
            'subject' => $session->subject,
            'issued_at' => $session->issuedAt,
            'expires_at' => $session->expiresAt,
            'claims' => json_encode($session->claims),
            'context' => json_encode($session->context),
        ]);
        $this->pdo->commit();
    }

    public function find(string $sessionId): ?SessionRecord
    {
        $this->ensureTable();
        $stmt = $this->pdo->prepare(sprintf('SELECT * FROM %s WHERE id = :id LIMIT 1', $this->table));
        $stmt->execute(['id' => $sessionId]);
        $row = $stmt->fetch(\PDO::FETCH_ASSOC);
        return $row ? $this->hydrate($row) : null;
    }

    public function revoke(string $sessionId): void
    {
        $this->ensureTable();
        $stmt = $this->pdo->prepare(sprintf('DELETE FROM %s WHERE id = :id', $this->table));
        $stmt->execute(['id' => $sessionId]);
    }

    public function findBySubject(string $subject): array
    {
        $this->ensureTable();
        $stmt = $this->pdo->prepare(sprintf(
            'SELECT * FROM %s WHERE subject = :subject ORDER BY issued_at DESC',
            $this->table
        ));
        $stmt->execute(['subject' => $subject]);
        $rows = $stmt->fetchAll(\PDO::FETCH_ASSOC);
        return array_map(fn(array $row) => $this->hydrate($row), $rows);
    }

    private function ensureTable(): void
    {
        if ($this->initialized) {
            return;
        }
        $sql = sprintf(
            'CREATE TABLE IF NOT EXISTS %s (
                id VARCHAR(128) PRIMARY KEY,
                subject VARCHAR(255) NOT NULL,
                issued_at BIGINT NOT NULL,
                expires_at BIGINT NOT NULL,
                claims TEXT NOT NULL,
                context TEXT NOT NULL
            )',
            $this->table
        );
        $this->pdo->exec($sql);
        $this->initialized = true;
    }

    /**
     * @param array<string,mixed> $row
     */
    private function hydrate(array $row): SessionRecord
    {
        return new SessionRecord(
            (string)$row['id'],
            (string)$row['subject'],
            (int)$row['issued_at'],
            (int)$row['expires_at'],
            json_decode((string)$row['claims'], true) ?: [],
            json_decode((string)$row['context'], true) ?: []
        );
    }
}
