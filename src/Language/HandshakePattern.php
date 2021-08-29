<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol\Language;

use Invariance\NoiseProtocol\Exception\NoiseProtocolException;

class HandshakePattern
{
    // patterns
    public const N = 'N';
    public const K = 'K';
    public const X = 'X';

    public const NN = 'NN';
    public const NK = 'NK';
    public const NX = 'NX';

    public const KN = 'KN';
    public const KK = 'KK';
    public const KX = 'KX';

    public const XN = 'XN';
    public const XK = 'XK';
    public const XX = 'XX';

    public const IN = 'IN';
    public const IK = 'IK';
    public const IX = 'IX';

    /** @var PreMessagePattern */
    private $initiator;

    /** @var PreMessagePattern */
    private $responder;

    /** @var MessagePattern[] */
    private $patterns;

    /**
     * @param MessagePattern ...$patterns
     */
    public function __construct(PreMessagePattern $initiator, PreMessagePattern $responder, ...$patterns)
    {
        $this->initiator = $initiator;
        $this->responder = $responder;
        $this->patterns = $patterns;
    }

    public function initiator(): PreMessagePattern
    {
        return $this->initiator;
    }

    public function responder(): PreMessagePattern
    {
        return $this->responder;
    }

    /**
     * @return MessagePattern[]
     */
    public function messagePatterns(): array
    {
        return $this->patterns;
    }

    public function localRequired(bool $initiator): bool
    {
        $preMessage = $initiator
            ? $this->initiator
            : $this->responder;

        if ($preMessage->hasToken(Token::S)) {
            return true;
        }

        $turnToWrite = $initiator;
        foreach ($this->patterns as $pattern) {
            if ($turnToWrite && $pattern->hasToken(Token::S)) {
                return true;
            }

            $turnToWrite = !$turnToWrite;
        }

        return false;
    }

    public function remoteRequired(bool $initiator): bool
    {
        $preMessage = $initiator
            ? $this->initiator
            : $this->responder;

        return $preMessage->hasToken(Token::S);
    }

    /**
     * @throws NoiseProtocolException - invalid handshake pattern
     */
    public static function instantiate(string $pattern): self
    {
        return match ($pattern) {
            self::N => new self(
                PreMessagePattern::empty(),
                PreMessagePattern::S(),
                new MessagePattern(Token::E, Token::ES)
            ),
            self::K => new self(
                PreMessagePattern::S(),
                PreMessagePattern::S(),
                new MessagePattern(Token::E, Token::ES, Token::SS)
            ),
            self::X => new self(
                PreMessagePattern::empty(),
                PreMessagePattern::S(),
                new MessagePattern(Token::E, Token::ES, Token::S, Token::SS)
            ),
            self::NN => new self(
                PreMessagePattern::empty(),
                PreMessagePattern::empty(),
                new MessagePattern(Token::E),
                new MessagePattern(Token::E, Token::EE)
            ),
            self::NK => new self(
                PreMessagePattern::empty(),
                PreMessagePattern::S(),
                new MessagePattern(Token::E, Token::ES),
                new MessagePattern(Token::E, Token::EE)
            ),
            self::NX => new self(
                PreMessagePattern::empty(),
                PreMessagePattern::empty(),
                new MessagePattern(Token::E),
                new MessagePattern(Token::E, Token::EE, Token::S, Token::ES)
            ),
            self::KN => new self(
                PreMessagePattern::S(),
                PreMessagePattern::empty(),
                new MessagePattern(Token::E),
                new MessagePattern(Token::E, Token::EE, Token::SE)
            ),
            self::KK => new self(
                PreMessagePattern::S(),
                PreMessagePattern::S(),
                new MessagePattern(Token::E, Token::ES, Token::SS),
                new MessagePattern(Token::E, Token::EE, Token::SE)
            ),
            self::KX => new self(
                PreMessagePattern::S(),
                PreMessagePattern::empty(),
                new MessagePattern(Token::E),
                new MessagePattern(Token::E, Token::EE, Token::SE, Token::S, Token::ES)
            ),
            self::XN => new self(
                PreMessagePattern::empty(),
                PreMessagePattern::empty(),
                new MessagePattern(Token::E),
                new MessagePattern(Token::E, Token::EE),
                new MessagePattern(Token::S, Token::SE)
            ),
            self::XK => new self(
                PreMessagePattern::empty(),
                PreMessagePattern::S(),
                new MessagePattern(Token::E, Token::ES),
                new MessagePattern(Token::E, Token::EE),
                new MessagePattern(Token::S, Token::SE)
            ),
            self::XX => new self(
                PreMessagePattern::empty(),
                PreMessagePattern::empty(),
                new MessagePattern(Token::E),
                new MessagePattern(Token::E, Token::EE, Token::S, Token::ES),
                new MessagePattern(Token::S, Token::SE)
            ),
            self::IN => new self(
                PreMessagePattern::empty(),
                PreMessagePattern::empty(),
                new MessagePattern(Token::E, Token::S),
                new MessagePattern(Token::E, Token::EE, Token::SE)
            ),
            self::IK => new self(
                PreMessagePattern::empty(),
                PreMessagePattern::S(),
                new MessagePattern(Token::E, Token::ES, Token::S, Token::SS),
                new MessagePattern(Token::E, Token::EE, Token::SE)
            ),
            self::IX => new self(
                PreMessagePattern::empty(),
                PreMessagePattern::empty(),
                new MessagePattern(Token::E, Token::S),
                new MessagePattern(Token::E, Token::EE, Token::SE, Token::S, Token::ES)
            ),
            default => throw new NoiseProtocolException('Invalid pattern name: %s.', $pattern),
        };
    }
}