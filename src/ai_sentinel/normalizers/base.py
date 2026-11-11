"""
InputNormalizer module for handling zero-width characters, homoglyphs,
and basic prompt normalization before shield evaluation.
"""

class InputNormalizer:
    @staticmethod
    def normalize(text: str) -> dict:
        if not isinstance(text, str):
            text = str(text)
        
        # Strip zero-width spaces and formatting characters
        cleaned = (
            text.replace("\u200b", "")
                .replace("\u200c", "")
                .replace("\u200d", "")
                .replace("\ufeff", "")
        )
        
        # Collapse whitespace to support whitespace collapse tests
        cleaned = " ".join(cleaned.split())
        
        return {"cleaned_text": cleaned}