<?php

namespace StackShield\Scanner\Checks;

abstract class AbstractCheck implements Check
{
    public function techniques(): array
    {
        return ['config'];
    }

    public function needsNetwork(): bool
    {
        return false;
    }
}
