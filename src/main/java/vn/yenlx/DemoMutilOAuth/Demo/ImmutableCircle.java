package vn.yenlx.DemoMutilOAuth.Demo;

public final class ImmutableCircle {
	private final Point center;
	private final int radius;
	public ImmutableCircle(Point center, int radius) {
		this.center = center;
		this.radius = radius;
	}
	public Point getCenter() {
		return center;
	}
	public int getRadius() {
		return radius;
	}
	
}
