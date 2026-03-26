from __future__ import annotations

import secrets
import string
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class PasswordGenerationConfig:
    length: int = 16
    use_uppercase: bool = True
    use_lowercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    symbols: str = "!@#$%^&*"
    exclude_ambiguous: bool = True
    enforce_strength: bool = True
    min_strength_score: int = 3
    history_size: int = 20


class PasswordGenerator:
    ambiguous_chars = set("lI10O")

    def __init__(self):
        self.recent_passwords: list[str] = []

    def normalize_config(self, config: PasswordGenerationConfig) -> PasswordGenerationConfig:
        length = min(64, max(8, int(config.length)))
        min_strength_score = min(4, max(0, int(config.min_strength_score)))
        history_size = min(200, max(1, int(config.history_size)))
        return PasswordGenerationConfig(
            length=length,
            use_uppercase=bool(config.use_uppercase),
            use_lowercase=bool(config.use_lowercase),
            use_digits=bool(config.use_digits),
            use_symbols=bool(config.use_symbols),
            symbols=str(config.symbols or "!@#$%^&*"),
            exclude_ambiguous=bool(config.exclude_ambiguous),
            enforce_strength=bool(config.enforce_strength),
            min_strength_score=min_strength_score,
            history_size=history_size,
        )

    def filter_ambiguous_chars(self, chars: str, exclude_ambiguous: bool) -> str:
        if not exclude_ambiguous:
            return chars
        return "".join(ch for ch in chars if ch not in self.ambiguous_chars)

    def collect_selected_sets(self, config: PasswordGenerationConfig) -> list[str]:
        selected_sets: list[str] = []
        if config.use_uppercase:
            selected_sets.append(self.filter_ambiguous_chars(string.ascii_uppercase, config.exclude_ambiguous))
        if config.use_lowercase:
            selected_sets.append(self.filter_ambiguous_chars(string.ascii_lowercase, config.exclude_ambiguous))
        if config.use_digits:
            selected_sets.append(self.filter_ambiguous_chars(string.digits, config.exclude_ambiguous))
        if config.use_symbols:
            selected_sets.append(self.filter_ambiguous_chars(config.symbols, config.exclude_ambiguous))
        selected_sets = [char_set for char_set in selected_sets if char_set]
        if not selected_sets:
            raise ValueError("Нужно выбрать хотя бы один набор символов.")
        if config.length < len(selected_sets):
            raise ValueError("Длина пароля меньше количества выбранных наборов символов.")
        return selected_sets

    def estimate_strength_score(self, password: str) -> int:
        score = 0
        if len(password) >= 12:
            score += 1
        if len(password) >= 16:
            score += 1
        variety = 0
        if any(ch.isupper() for ch in password):
            variety += 1
        if any(ch.islower() for ch in password):
            variety += 1
        if any(ch.isdigit() for ch in password):
            variety += 1
        if any(not ch.isalnum() for ch in password):
            variety += 1
        if variety >= 3:
            score += 1
        if variety == 4 and len(password) >= 20:
            score += 1
        return min(4, max(0, score))

    def shuffle_chars(self, chars: list[str]) -> None:
        for index in range(len(chars) - 1, 0, -1):
            swap_index = secrets.randbelow(index + 1)
            chars[index], chars[swap_index] = chars[swap_index], chars[index]

    def make_candidate_password(self, config: PasswordGenerationConfig) -> str:
        selected_sets = self.collect_selected_sets(config)
        required_chars = [secrets.choice(char_set) for char_set in selected_sets]
        combined_pool = "".join(selected_sets)
        remaining_count = config.length - len(required_chars)
        tail = [secrets.choice(combined_pool) for _ in range(remaining_count)]
        password_chars = required_chars + tail
        self.shuffle_chars(password_chars)
        return "".join(password_chars)

    def remember_password(self, password: str, history_size: int) -> None:
        self.recent_passwords.append(password)
        if len(self.recent_passwords) > history_size:
            trim_count = len(self.recent_passwords) - history_size
            del self.recent_passwords[0:trim_count]

    def generate(self, config: Optional[PasswordGenerationConfig] = None) -> str:
        safe_config = self.normalize_config(config or PasswordGenerationConfig())
        for _ in range(500):
            candidate = self.make_candidate_password(safe_config)
            if safe_config.enforce_strength:
                if self.estimate_strength_score(candidate) < safe_config.min_strength_score:
                    continue
            if candidate in self.recent_passwords:
                continue
            self.remember_password(candidate, safe_config.history_size)
            return candidate
        raise RuntimeError("Не удалось сгенерировать пароль с заданными ограничениями.")
