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
     * @throws NoiseProtocolException
     */
    public static function instantiate(string $pattern): self
    {
        switch ($pattern) {
            case self::N:
                return new self(
                    PreMessagePattern::empty(),
                    PreMessagePattern::S(),
                    new MessagePattern(Token::E, Token::ES)
                );

            case self::K:
                return new self(
                    PreMessagePattern::S(),
                    PreMessagePattern::S(),
                    new MessagePattern(Token::E, Token::ES, Token::SS)
                );

            case self::X:
                return new self(
                    PreMessagePattern::empty(),
                    PreMessagePattern::S(),
                    new MessagePattern(Token::E, Token::ES, Token::S, Token::SS)
                );

            case self::NN:
                return new self(
                    PreMessagePattern::empty(),
                    PreMessagePattern::empty(),
                    new MessagePattern(Token::E),
                    new MessagePattern(Token::E, Token::EE)
                );

            case self::NK:
                return new self(
                    PreMessagePattern::empty(),
                    PreMessagePattern::S(),
                    new MessagePattern(Token::E, Token::ES),
                    new MessagePattern(Token::E, Token::EE)
                );

            case self::NX:
                return new self(
                    PreMessagePattern::empty(),
                    PreMessagePattern::empty(),
                    new MessagePattern(Token::E),
                    new MessagePattern(Token::E, Token::EE, Token::S, Token::ES)
                );

            case self::KN:
                return new self(
                    PreMessagePattern::S(),
                    PreMessagePattern::empty(),
                    new MessagePattern(Token::E),
                    new MessagePattern(Token::E, Token::EE, Token::SE)
                );

            case self::KK:
                return new self(
                    PreMessagePattern::S(),
                    PreMessagePattern::S(),
                    new MessagePattern(Token::E, Token::ES, Token::SS),
                    new MessagePattern(Token::E, Token::EE, Token::SE)
                );

            case self::KX:
                return new self(
                    PreMessagePattern::S(),
                    PreMessagePattern::empty(),
                    new MessagePattern(Token::E),
                    new MessagePattern(Token::E, Token::EE, Token::SE, Token::S, Token::ES)
                );

            case self::XN:
                return new self(
                    PreMessagePattern::empty(),
                    PreMessagePattern::empty(),
                    new MessagePattern(Token::E),
                    new MessagePattern(Token::E, Token::EE),
                    new MessagePattern(Token::S, Token::SE)
                );

            case self::XK:
                return new self(
                    PreMessagePattern::empty(),
                    PreMessagePattern::S(),
                    new MessagePattern(Token::E, Token::ES),
                    new MessagePattern(Token::E, Token::EE),
                    new MessagePattern(Token::S, Token::SE)
                );

            case self::XX:
                return new self(
                    PreMessagePattern::empty(),
                    PreMessagePattern::empty(),
                    new MessagePattern(Token::E),
                    new MessagePattern(Token::E, Token::EE, Token::S, Token::ES),
                    new MessagePattern(Token::S, Token::SE)
                );

            case self::IN:
                return new self(
                    PreMessagePattern::empty(),
                    PreMessagePattern::empty(),
                    new MessagePattern(Token::E, Token::S),
                    new MessagePattern(Token::E, Token::EE, Token::SE)
                );

            case self::IK:
                return new self(
                    PreMessagePattern::empty(),
                    PreMessagePattern::S(),
                    new MessagePattern(Token::E, Token::ES, Token::S, Token::SS),
                    new MessagePattern(Token::E, Token::EE, Token::SE)
                );

            case self::IX:
                return new self(
                    PreMessagePattern::empty(),
                    PreMessagePattern::empty(),
                    new MessagePattern(Token::E, Token::S),
                    new MessagePattern(Token::E, Token::EE, Token::SE, Token::S, Token::ES)
                );
            default:
                throw new NoiseProtocolException('Invalid pattern name: %s.', $pattern);
        }
    }
}