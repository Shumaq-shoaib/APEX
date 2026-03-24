from sklearn.base import BaseEstimator, TransformerMixin

def extract_text_field(df):
    return (
        df['request.url'].fillna('').astype(str) + ' ' +
        df['request.body'].fillna('').astype(str) + ' ' +
        df['request.headers.Cookie'].fillna('').astype(str) + ' ' +
        df['request.headers.User-Agent'].fillna('').astype(str)
    )

class TextCombiner(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None): 
        return self
    def transform(self, X): 
        return extract_text_field(X)
