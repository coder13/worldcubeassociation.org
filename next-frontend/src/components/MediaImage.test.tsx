import { render, screen } from "@testing-library/react";

import { MediaImage } from "@/components/MediaImage";
import { Provider } from "@/components/ui/provider";
import type { Media } from "@/types/payload";

const media: Media = {
  id: "media-id",
  alt: "A test image",
  createdAt: "2026-01-01T00:00:00.000Z",
  updatedAt: "2026-01-01T00:00:00.000Z",
  url: "https://example.com/full.jpg",
  width: 1920,
  height: 1277,
  sizes: {
    thumbnail: {
      url: "https://example.com/thumbnail.jpg",
      width: 400,
      height: 300,
    },
    card: {
      url: "https://example.com/card.jpg",
      width: 768,
      height: 512,
    },
  },
};

describe("MediaImage", () => {
  it("passes responsive sizing information to the image", () => {
    render(
      <Provider>
        <MediaImage media={media} sizes="(max-width: 768px) 100vw, 564px" />
      </Provider>,
    );

    const image = screen.getByRole("img", { name: "A test image" });

    expect(image).toHaveAttribute("sizes", "(max-width: 768px) 100vw, 564px");
    expect(image).toHaveAttribute(
      "srcset",
      "https://example.com/thumbnail.jpg 400w, https://example.com/card.jpg 768w, https://example.com/full.jpg 1920w",
    );
  });
});
