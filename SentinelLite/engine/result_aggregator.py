class ResultAggregator:
    def combine(self, *finding_lists):
        combined = []
        for findings in finding_lists:
            if findings:
                combined.extend(findings)
        return combined
