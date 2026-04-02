"""Output validation layer for AI agent responses.

Validates LLM outputs before they reach the customer:
- Product ID existence check against the catalog
- Policy compliance verification
- Reply quality checks
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

log = logging.getLogger(__name__)


class OutputValidator:
    """Post-LLM validation pipeline that catches hallucinations and policy violations."""

    # ---- Product ID validation ----
    @staticmethod
    def validate_product_ids(
        output_data: dict[str, Any],
        catalog_products: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Check that recommended product IDs actually exist in the catalog.

        Returns:
            {
                "valid": True/False,
                "checked_ids": [...],
                "invalid_ids": [...],
                "corrected_ids": [...],  # IDs that were removed
            }
        """
        recommended_ids = [
            str(x).strip()
            for x in (output_data.get("recommended_product_ids") or [])
            if str(x).strip()
        ]
        if not recommended_ids:
            return {"valid": True, "checked_ids": [], "invalid_ids": [], "corrected_ids": []}

        # Build a set of known product IDs from catalog
        known_ids: set[str] = set()
        for product in catalog_products:
            for key in ("retailer_id", "id", "product_id"):
                val = str(product.get(key) or "").strip()
                if val:
                    known_ids.add(val)

        invalid_ids = [pid for pid in recommended_ids if pid not in known_ids]
        corrected_ids = [pid for pid in recommended_ids if pid in known_ids]

        return {
            "valid": len(invalid_ids) == 0,
            "checked_ids": recommended_ids,
            "invalid_ids": invalid_ids,
            "corrected_ids": corrected_ids,
        }

    # ---- Policy compliance check ----
    @staticmethod
    def validate_policy_compliance(
        reply_text: str,
        policies: list[dict[str, Any]],
        output_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Check if the reply contradicts or fabricates policy information.

        Checks:
        1. If the reply mentions delivery times/prices not in any policy
        2. If the reply mentions return/refund terms not in any policy
        3. If the reply invents specific guarantees or promises
        """
        reply_lower = str(reply_text or "").lower()
        if not reply_lower.strip():
            return {"valid": True, "warnings": []}

        warnings: list[str] = []
        policy_text_combined = " ".join(
            str(p.get("content") or "").lower()
            for p in policies
            if str(p.get("status") or "approved") == "approved"
        )

        # Check for fabricated delivery times
        delivery_time_pattern = re.compile(
            r"(\d+)\s*(?:hours?|heures?|jours?|days?|ساعات?|أيام|يوم|ساعة)",
            re.IGNORECASE
        )
        reply_times = delivery_time_pattern.findall(reply_lower)
        if reply_times and not delivery_time_pattern.search(policy_text_combined):
            warnings.append(
                f"reply_mentions_delivery_time_not_in_policy: "
                f"Reply mentions specific time ({', '.join(reply_times)}) but no policy confirms this."
            )

        # Check for fabricated prices/amounts
        price_pattern = re.compile(
            r"(\d+)\s*(?:dh|mad|درهم|dirhams?)",
            re.IGNORECASE
        )
        reply_prices = price_pattern.findall(reply_lower)
        if reply_prices and "delivery" in str(output_data.get("intent") or "").lower():
            if not price_pattern.search(policy_text_combined):
                warnings.append(
                    f"reply_mentions_price_not_in_policy: "
                    f"Reply mentions a price ({', '.join(reply_prices)} DH) but no policy confirms this."
                )

        # Check for fabricated guarantees
        guarantee_markers = [
            "guarantee", "garantie", "ضمان",
            "100%", "certifié", "certified",
        ]
        for marker in guarantee_markers:
            if marker in reply_lower and marker not in policy_text_combined:
                warnings.append(
                    f"fabricated_guarantee: Reply contains '{marker}' which is not in any approved policy."
                )

        # Check for refund promises without policy backing
        refund_markers = [
            ("full refund", "remboursement intégral", "استرجاع كامل"),
            ("free return", "retour gratuit", "إرجاع مجاني"),
        ]
        for marker_group in refund_markers:
            for marker in marker_group:
                if marker in reply_lower and marker not in policy_text_combined:
                    warnings.append(
                        f"refund_promise_not_in_policy: Reply promises '{marker}' which is not in any policy."
                    )

        return {
            "valid": len(warnings) == 0,
            "warnings": warnings,
        }

    # ---- Reply quality checks ----
    @staticmethod
    def validate_reply_quality(
        reply_text: str,
        output_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Run basic quality checks on the generated reply."""
        warnings: list[str] = []
        reply = str(reply_text or "").strip()

        if not reply and not output_data.get("should_handoff"):
            warnings.append("empty_reply: Reply text is empty but no handoff requested.")

        # Check for excessively long replies (WhatsApp best practice: keep it short)
        if len(reply) > 500:
            warnings.append(f"reply_too_long: Reply is {len(reply)} chars, recommended max is 500.")

        # Check for Latin transliteration of Arabic (common LLM failure)
        latin_arabic_patterns = [
            r"\bsalam\b", r"\bshukran\b", r"\binshallah\b", r"\byallah\b",
            r"\bhabibi\b", r"\bmabrook\b", r"\bmarhaba\b",
        ]
        for pattern in latin_arabic_patterns:
            if re.search(pattern, reply, re.IGNORECASE):
                # Only warn if the detected language is Arabic/Darija
                lang = str(output_data.get("language") or "").lower()
                if lang in ("ar", "darija", "mixed"):
                    warnings.append(
                        f"latin_transliteration: Reply contains Latin transliteration '{pattern}' "
                        f"but language is {lang}. Should use Arabic script."
                    )
                    break

        # Check for placeholders/template artifacts
        placeholder_patterns = [
            r"\[.*?\]",  # [placeholder]
            r"\{.*?\}",  # {placeholder}
            r"<.*?>",    # <placeholder>
            r"INSERT",
            r"TODO",
            r"PLACEHOLDER",
        ]
        for pattern in placeholder_patterns:
            if re.search(pattern, reply, re.IGNORECASE):
                warnings.append(f"contains_placeholder: Reply may contain a template placeholder ({pattern}).")
                break

        return {
            "valid": len(warnings) == 0,
            "warnings": warnings,
        }

    # ---- Full validation pipeline ----
    @classmethod
    def validate_output(
        cls,
        *,
        output_data: dict[str, Any],
        catalog_products: list[dict[str, Any]] | None = None,
        policies: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Run the full validation pipeline on LLM output.

        Returns:
            {
                "valid": True/False (all checks pass),
                "product_check": {...},
                "policy_check": {...},
                "quality_check": {...},
                "all_warnings": [...],
                "corrected_output": {...} or None,
            }
        """
        reply_text = str(output_data.get("reply_text") or "").strip()

        # 1. Product ID validation
        product_check = cls.validate_product_ids(
            output_data,
            catalog_products or [],
        )

        # 2. Policy compliance
        policy_check = cls.validate_policy_compliance(
            reply_text,
            policies or [],
            output_data,
        )

        # 3. Reply quality
        quality_check = cls.validate_reply_quality(
            reply_text,
            output_data,
        )

        all_warnings = (
            [f"product: {w}" for w in product_check.get("warnings", [])]
            + [f"product: invalid_id_{pid}" for pid in product_check.get("invalid_ids", [])]
            + [f"policy: {w}" for w in policy_check.get("warnings", [])]
            + [f"quality: {w}" for w in quality_check.get("warnings", [])]
        )

        overall_valid = (
            product_check.get("valid", True)
            and policy_check.get("valid", True)
            and quality_check.get("valid", True)
        )

        # Auto-correct: remove invalid product IDs from output
        corrected_output = None
        if not product_check.get("valid"):
            corrected_output = dict(output_data)
            corrected_output["recommended_product_ids"] = product_check.get("corrected_ids", [])
            corrected_output["_validation_corrected"] = True

        return {
            "valid": overall_valid,
            "product_check": product_check,
            "policy_check": policy_check,
            "quality_check": quality_check,
            "all_warnings": all_warnings,
            "corrected_output": corrected_output,
        }
